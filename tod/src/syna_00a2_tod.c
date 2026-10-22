/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * libfprint-TOD driver for the Synaptics 06cb:00a2 fingerprint reader.
 *
 * The device work (TLS, calibration, scans, the template database) is in the
 * Rust crate syna-00a2, behind the C ABI in lib.rs. This file adapts it to
 * libfprint: each action runs the blocking Rust calls in a GTask worker
 * thread, and everything that touches libfprint happens in the device's main
 * context. Templates live on the sensor, under one user record per Linux uid,
 * and the sensor matches them; a print only names its stored finger.
 */

#define _GNU_SOURCE /* dladdr */
#define FP_COMPONENT "syna_00a2"

#include <dlfcn.h>
#include <pwd.h>

#include "drivers_api.h"

/* Touch-and-lift placements per enrollment (M5b evaluated 10) */
#define SYNA_ENROLL_STAGES 10

/* The Rust side (lib.rs) */
typedef struct SynaHandle SynaHandle;
enum {
  SYNA_OK = 0, SYNA_IMAGE = 0, SYNA_RETRY = 1, SYNA_CANCELLED = 2, SYNA_MATCH = 3,
  SYNA_NO_MATCH = 4, SYNA_DATA_FULL = 5, SYNA_NOT_FOUND = 6, SYNA_ERROR = -1,
};
enum { SYNA_STATUS_NEEDED = 1, SYNA_STATUS_PRESENT = 2 };
typedef struct
{
  guint32 uid;     /* Linux uid in the user record's SID */
  guint16 subtype; /* WinBio finger position, 1..10 */
} SynaPrint;
SynaHandle *syna_open (guint8 bus, guint8 address, char **error);
void syna_close (SynaHandle *handle);
gsize syna_image_size (void);
int syna_capture (SynaHandle *handle,
                  int (*is_cancelled) (gpointer user),
                  void (*on_status) (gpointer user, int status),
                  gpointer user,
                  guint8 *image,
                  char **error);
int syna_chip_enroll (SynaHandle *handle, guint32 uid, guint16 subtype,
                      const guint8 *images, gsize count, SynaPrint *out, char **error);
int syna_chip_identify (SynaHandle *handle, gint64 restrict_uid,
                        int (*is_cancelled) (gpointer user),
                        void (*on_status) (gpointer user, int status),
                        gpointer status_user, SynaPrint *out, char **error);
int syna_chip_list (SynaHandle *handle, SynaPrint **out, gsize *len, char **error);
void syna_prints_free (SynaPrint *prints, gsize len);
int syna_chip_delete (SynaHandle *handle, const SynaPrint *print, char **error);
void syna_string_free (char *message);

struct _FpiDeviceSyna00a2
{
  FpDevice      parent;
  GMainContext *main_context;
  SynaHandle   *handle;
  gint          cancelling; /* atomic */
};

G_DECLARE_FINAL_TYPE (FpiDeviceSyna00a2, fpi_device_syna_00a2, FPI, DEVICE_SYNA_00A2, FpDevice)
G_DEFINE_TYPE (FpiDeviceSyna00a2, fpi_device_syna_00a2, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = 0x06cb, .pid = 0x00a2 },
  { .vid = 0, .pid = 0 },
};

/* Worker results for verify and identify: a print index, no match, or a
 * rejected placement */
#define SYNA_OUTCOME_NO_MATCH -1
#define SYNA_OUTCOME_RETRY -2

/* A print's fpi-data: SynaPrint's fields */
#define SYNA_PRINT_FORMAT "(uq)"

static GError *
take_error (char *message)
{
  GError *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "%s",
                                            message ? message : "unknown error");

  syna_string_free (message);
  return error;
}

static GError *
cancelled_error (void)
{
  return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation was cancelled");
}

/* Reports from worker threads, delivered in the main context */

typedef struct
{
  FpDevice           *device;
  FpFingerStatusFlags status;
  gint                stage;
  GError             *retry;
} Report;

static void
report_free (gpointer data)
{
  Report *report = data;

  g_object_unref (report->device);
  g_clear_error (&report->retry);
  g_free (report);
}

static gboolean
report_status_cb (gpointer data)
{
  Report *report = data;

  fpi_device_report_finger_status (report->device, report->status);
  return G_SOURCE_REMOVE;
}

static gboolean
report_enroll_cb (gpointer data)
{
  Report *report = data;

  fpi_device_enroll_progress (report->device, report->stage, NULL,
                              g_steal_pointer (&report->retry));
  return G_SOURCE_REMOVE;
}

static void
invoke (FpDevice *device, GSourceFunc func, Report *report)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (device);

  report->device = g_object_ref (device);
  g_main_context_invoke_full (self->main_context, G_PRIORITY_DEFAULT, func, report, report_free);
}

static int
is_cancelled (gpointer user)
{
  return g_atomic_int_get (&FPI_DEVICE_SYNA_00A2 (user)->cancelling);
}

static void
on_status (gpointer user, int status)
{
  Report *report = g_new0 (Report, 1);

  report->status = status == SYNA_STATUS_NEEDED ? FP_FINGER_STATUS_NEEDED : FP_FINGER_STATUS_PRESENT;
  invoke (FP_DEVICE (user), report_status_cb, report);
}

/* Open and close */

static void
open_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  const guint8 *where = task_data;
  char *message = NULL;
  SynaHandle *handle = syna_open (where[0], where[1], &message);

  if (handle)
    g_task_return_pointer (task, handle, NULL);
  else
    g_task_return_error (task, take_error (message));
}

static void
open_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  GError *error = NULL;

  self->handle = g_task_propagate_pointer (G_TASK (result), &error);
  fpi_device_open_complete (FP_DEVICE (self), error);
}

static void
syna_open_device (FpDevice *device)
{
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  guint8 *where = g_new (guint8, 2);
  GTask *task = g_task_new (device, NULL, open_done, NULL);

  /* libfprint has opened the GUsbDevice but claims nothing; the Rust side
   * opens its own handle to the same device and claims interface 0 */
  where[0] = g_usb_device_get_bus (usb);
  where[1] = g_usb_device_get_address (usb);
  g_task_set_task_data (task, where, g_free);
  g_task_run_in_thread (task, open_thread);
  g_object_unref (task);
}

static void
close_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);

  syna_close (g_steal_pointer (&self->handle));
  g_task_return_boolean (task, TRUE);
}

static void
close_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  fpi_device_close_complete (FP_DEVICE (source), NULL);
}

static void
syna_close_device (FpDevice *device)
{
  GTask *task = g_task_new (device, NULL, close_done, NULL);

  g_task_run_in_thread (task, close_thread);
  g_object_unref (task);
}

/* Prints: device-stored, naming a finger record on the sensor */

/* WinBio finger positions: right thumb..little 1..5, left 6..10; 0 = none */
static guint16
subtype_for_finger (FpFinger finger)
{
  if (finger >= FP_FINGER_RIGHT_THUMB && finger <= FP_FINGER_RIGHT_LITTLE)
    return finger - FP_FINGER_RIGHT_THUMB + 1;
  if (finger >= FP_FINGER_LEFT_THUMB && finger <= FP_FINGER_LEFT_LITTLE)
    return finger - FP_FINGER_LEFT_THUMB + 6;
  return 0;
}

static FpFinger
finger_for_subtype (guint16 subtype)
{
  if (subtype >= 1 && subtype <= 5)
    return FP_FINGER_RIGHT_THUMB + subtype - 1;
  if (subtype >= 6 && subtype <= 10)
    return FP_FINGER_LEFT_THUMB + subtype - 6;
  return FP_FINGER_UNKNOWN;
}

static gboolean
print_get_stored (FpPrint *print, SynaPrint *out)
{
  g_autoptr(GVariant) data = NULL;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, SYNA_PRINT_FORMAT, FALSE))
    return FALSE;
  g_variant_get (data, SYNA_PRINT_FORMAT, &out->uid, &out->subtype);
  return TRUE;
}

static void
print_set_stored (FpPrint *print, const SynaPrint *stored)
{
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data",
                g_variant_new (SYNA_PRINT_FORMAT, stored->uid, stored->subtype),
                NULL);
}

/* Capturing in a worker thread */

/* One placement into `image`: SYNA_IMAGE, SYNA_RETRY, or an error set */
static int
capture (FpiDeviceSyna00a2 *self, guint8 *image, GError **error)
{
  char *message = NULL;
  int outcome = syna_capture (self->handle, is_cancelled, on_status, self, image, &message);

  if (outcome == SYNA_CANCELLED)
    g_propagate_error (error, cancelled_error ());
  else if (outcome == SYNA_ERROR)
    g_propagate_error (error, take_error (message));
  return outcome;
}

/* Enroll: touch-and-lift placements, then the template goes onto the sensor */

typedef struct
{
  guint32 uid;
  guint16 subtype;
} EnrollData;

static void
enroll_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  EnrollData *data = task_data;
  gsize size = syna_image_size ();
  g_autofree guint8 *image = g_malloc (size);
  g_autoptr(GByteArray) images = g_byte_array_new ();
  gint stages = 0;
  char *message = NULL;
  SynaPrint *stored;
  int outcome;

  while (stages < SYNA_ENROLL_STAGES)
    {
      GError *error = NULL;
      Report *report;

      outcome = capture (self, image, &error);
      if (error)
        {
          g_task_return_error (task, error);
          return;
        }
      report = g_new0 (Report, 1);
      if (outcome == SYNA_IMAGE)
        {
          g_byte_array_append (images, image, size);
          stages++;
        }
      else
        {
          report->retry = fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
        }
      report->stage = stages;
      invoke (FP_DEVICE (self), report_enroll_cb, report);
    }

  stored = g_new0 (SynaPrint, 1);
  outcome = syna_chip_enroll (self->handle, data->uid, data->subtype, images->data, stages, stored, &message);
  if (outcome == SYNA_OK)
    {
      g_task_return_pointer (task, stored, g_free);
      return;
    }
  g_free (stored);
  if (outcome == SYNA_DATA_FULL)
    g_task_return_error (task, fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL));
  else
    g_task_return_error (task, take_error (message));
}

static void
enroll_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  GError *error = NULL;
  g_autofree SynaPrint *stored = g_task_propagate_pointer (G_TASK (result), &error);
  FpPrint *print = NULL;

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (error)
    {
      fpi_device_enroll_complete (device, NULL, error);
      return;
    }
  fpi_device_get_enroll_data (device, &print);
  print_set_stored (print, stored);
  fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
syna_enroll (FpDevice *device)
{
  FpPrint *print = NULL;
  EnrollData *data = g_new0 (EnrollData, 1);
  const char *username;
  struct passwd entry, *found = NULL;
  char buffer[4096];
  GTask *task;

  fpi_device_get_enroll_data (device, &print);
  data->subtype = subtype_for_finger (fp_print_get_finger (print));
  username = fp_print_get_username (print);
  if (username)
    getpwnam_r (username, &entry, buffer, sizeof buffer, &found);
  if (!data->subtype || !found)
    {
      g_free (data);
      /* The user record on the sensor belongs to the uid, so both are needed */
      fpi_device_enroll_complete (device, NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "Enrolling needs a finger position and a known username"));
      return;
    }
  data->uid = found->pw_uid;

  task = g_task_new (device, NULL, enroll_done, NULL);
  g_atomic_int_set (&FPI_DEVICE_SYNA_00A2 (device)->cancelling, FALSE);
  g_task_set_task_data (task, data, g_free);
  g_task_run_in_thread (task, enroll_thread);
  g_object_unref (task);
}

/* Verify and identify: one identify-mode touch, matched by the sensor */

typedef struct
{
  gint64  uid;     /* restrict the match to this uid's fingers; -1 = any */
  GArray *prints;  /* SynaPrint per gallery entry, subtype 0 if not ours */
} MatchData;

static void
match_data_free (gpointer data)
{
  MatchData *match = data;

  g_array_unref (match->prints);
  g_free (match);
}

static void
match_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  MatchData *data = task_data;
  SynaPrint found = { 0 };
  char *message = NULL;
  int outcome = syna_chip_identify (self->handle, data->uid, is_cancelled, on_status, self, &found, &message);

  if (outcome == SYNA_CANCELLED)
    g_task_return_error (task, cancelled_error ());
  else if (outcome == SYNA_ERROR)
    g_task_return_error (task, take_error (message));
  else if (outcome == SYNA_RETRY)
    g_task_return_int (task, SYNA_OUTCOME_RETRY);
  else
    {
      /* (uid, subtype) names one finger on the sensor */
      for (guint i = 0; outcome == SYNA_MATCH && i < data->prints->len; i++)
        {
          SynaPrint *print = &g_array_index (data->prints, SynaPrint, i);

          if (print->subtype && print->uid == found.uid && print->subtype == found.subtype)
            {
              g_task_return_int (task, i);
              return;
            }
        }
      if (outcome == SYNA_MATCH)
        fp_dbg ("Matched uid %u finger %u, which is not in the gallery", found.uid, found.subtype);
      g_task_return_int (task, SYNA_OUTCOME_NO_MATCH);
    }
}

static void
start_match (FpDevice *device, GPtrArray *prints, GAsyncReadyCallback done)
{
  MatchData *data = g_new0 (MatchData, 1);
  GTask *task = g_task_new (device, NULL, done, NULL);
  gboolean one_user = TRUE;

  data->uid = -1;
  data->prints = g_array_sized_new (FALSE, TRUE, sizeof (SynaPrint), prints->len);
  for (guint i = 0; i < prints->len; i++)
    {
      SynaPrint stored = { 0 };

      if (!print_get_stored (g_ptr_array_index (prints, i), &stored))
        fp_warn ("Skipping a print this driver didn't store");
      else if (data->uid >= 0 && stored.uid != data->uid)
        one_user = FALSE;
      else
        data->uid = stored.uid;
      g_array_append_val (data->prints, stored);
    }
  /* The sensor matches one scan once, so a gallery spanning users is matched
   * against every Linux user and filtered here */
  if (!one_user)
    data->uid = -1;
  g_atomic_int_set (&FPI_DEVICE_SYNA_00A2 (device)->cancelling, FALSE);
  g_task_set_task_data (task, data, match_data_free);
  g_task_run_in_thread (task, match_thread);
  g_object_unref (task);
}

static void
verify_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  GError *error = NULL;
  gssize match = g_task_propagate_int (G_TASK (result), &error);

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (error)
    {
      fpi_device_verify_complete (device, error);
      return;
    }
  if (match == SYNA_OUTCOME_RETRY)
    fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
  else
    fpi_device_verify_report (device, match >= 0 ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, NULL, NULL);
  fpi_device_verify_complete (device, NULL);
}

static void
syna_verify (FpDevice *device)
{
  g_autoptr(GPtrArray) prints = g_ptr_array_new ();
  FpPrint *print = NULL;
  SynaPrint stored;

  fpi_device_get_verify_data (device, &print);
  if (!print_get_stored (print, &stored))
    {
      fpi_device_verify_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }
  g_ptr_array_add (prints, print);
  start_match (device, prints, verify_done);
}

static void
identify_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  GError *error = NULL;
  gssize match = g_task_propagate_int (G_TASK (result), &error);
  GPtrArray *prints = NULL;

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (error)
    {
      fpi_device_identify_complete (device, error);
      return;
    }
  fpi_device_get_identify_data (device, &prints);
  if (match == SYNA_OUTCOME_RETRY)
    fpi_device_identify_report (device, NULL, NULL, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
  else
    fpi_device_identify_report (device, match >= 0 ? g_ptr_array_index (prints, match) : NULL, NULL, NULL);
  fpi_device_identify_complete (device, NULL);
}

static void
syna_identify (FpDevice *device)
{
  GPtrArray *prints = NULL;

  fpi_device_get_identify_data (device, &prints);
  start_match (device, prints, identify_done);
}

/* List and delete: only fingers under Linux-owned user records */

typedef struct
{
  SynaPrint *prints;
  gsize      len;
} Listing;

static void
listing_free (gpointer data)
{
  Listing *listing = data;

  syna_prints_free (listing->prints, listing->len);
  g_free (listing);
}

static void
list_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  Listing *listing = g_new0 (Listing, 1);
  char *message = NULL;

  if (syna_chip_list (self->handle, &listing->prints, &listing->len, &message) == SYNA_OK)
    {
      g_task_return_pointer (task, listing, listing_free);
      return;
    }
  g_free (listing);
  g_task_return_error (task, take_error (message));
}

static void
list_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  GError *error = NULL;
  Listing *listing = g_task_propagate_pointer (G_TASK (result), &error);
  GPtrArray *prints;

  if (error)
    {
      fpi_device_list_complete (device, NULL, error);
      return;
    }
  prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (gsize i = 0; i < listing->len; i++)
    {
      FpPrint *print = fp_print_new (device);
      struct passwd entry, *found = NULL;
      char buffer[4096];

      print_set_stored (print, &listing->prints[i]);
      fp_print_set_finger (print, finger_for_subtype (listing->prints[i].subtype));
      if (getpwuid_r (listing->prints[i].uid, &entry, buffer, sizeof buffer, &found) == 0 && found)
        fp_print_set_username (print, found->pw_name);
      /* FpPrint starts floating: without the sink, a caller that sinks it
       * (PyGObject) loses it when the array is freed */
      g_ptr_array_add (prints, g_object_ref_sink (print));
    }
  listing_free (listing);
  fpi_device_list_complete (device, prints, NULL);
}

static void
syna_list (FpDevice *device)
{
  GTask *task = g_task_new (device, NULL, list_done, NULL);

  g_task_run_in_thread (task, list_thread);
  g_object_unref (task);
}

static void
delete_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  char *message = NULL;
  int outcome = syna_chip_delete (self->handle, task_data, &message);

  if (outcome == SYNA_OK)
    g_task_return_boolean (task, TRUE);
  else if (outcome == SYNA_NOT_FOUND)
    g_task_return_error (task, fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
  else
    g_task_return_error (task, take_error (message));
}

static void
delete_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  GError *error = NULL;

  g_task_propagate_boolean (G_TASK (result), &error);
  fpi_device_delete_complete (FP_DEVICE (source), error);
}

static void
syna_delete (FpDevice *device)
{
  FpPrint *print = NULL;
  SynaPrint *stored = g_new0 (SynaPrint, 1);
  GTask *task;

  fpi_device_get_delete_data (device, &print);
  if (!print_get_stored (print, stored))
    {
      g_free (stored);
      fpi_device_delete_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      return;
    }
  task = g_task_new (device, NULL, delete_done, NULL);
  g_task_set_task_data (task, stored, g_free);
  g_task_run_in_thread (task, delete_thread);
  g_object_unref (task);
}

/* The worker polls this flag, so a scan stops within about 100 ms */
static void
syna_cancel (FpDevice *device)
{
  g_atomic_int_set (&FPI_DEVICE_SYNA_00A2 (device)->cancelling, TRUE);
}

/* G_DEFINE_TYPE registers a static type, which GLib can't unregister, but
 * libfprint-tod g_module_close()s drivers when a context is torn down. A
 * device that outlived its context then finalized in unloaded code: a
 * segfault at exit (robustness run r1, reproduced without device I/O). So
 * the module stays loaded for good. */
static void
pin_module (void)
{
  Dl_info info;

  if (!dladdr ((void *) pin_module, &info) || !info.dli_fname ||
      !dlopen (info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE))
    fp_warn ("Could not keep the driver module loaded; exiting with devices still alive may crash");
}

static void
fpi_device_syna_00a2_init (FpiDeviceSyna00a2 *self)
{
  self->main_context = g_main_context_ref_thread_default ();
}

static void
fpi_device_syna_00a2_finalize (GObject *object)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (object);

  syna_close (g_steal_pointer (&self->handle));
  g_main_context_unref (self->main_context);
  G_OBJECT_CLASS (fpi_device_syna_00a2_parent_class)->finalize (object);
}

static void
fpi_device_syna_00a2_class_init (FpiDeviceSyna00a2Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  pin_module ();
  G_OBJECT_CLASS (klass)->finalize = fpi_device_syna_00a2_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Synaptics Metallica MOH Touch (06cb:00a2)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = SYNA_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* A press sensor that idles between scans: no heating model */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = syna_open_device;
  dev_class->close = syna_close_device;
  dev_class->enroll = syna_enroll;
  dev_class->verify = syna_verify;
  dev_class->identify = syna_identify;
  dev_class->list = syna_list;
  dev_class->delete = syna_delete;
  dev_class->cancel = syna_cancel;
  /* clear_storage stays NULL: wiping would take records Linux didn't create
   * (the Windows user's). The TOD loader fills in the feature flags. */
}
