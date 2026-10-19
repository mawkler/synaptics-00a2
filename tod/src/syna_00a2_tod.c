/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * libfprint-TOD driver for the Synaptics 06cb:00a2 fingerprint reader.
 *
 * The device work (TLS, calibration, scans, matching) is in the Rust crate
 * syna-00a2, behind the C ABI in lib.rs. This file adapts it to libfprint:
 * each action runs the blocking Rust calls in a GTask worker thread, and
 * everything that touches libfprint happens in the device's main context.
 * Templates are the enrolled images, stored host-side by fprintd.
 */

#define _GNU_SOURCE /* dladdr */
#define FP_COMPONENT "syna_00a2"

#include <dlfcn.h>
#include <math.h>

#include "drivers_api.h"

/* Touch-and-lift placements per enrollment (M5b evaluated 10) */
#define SYNA_ENROLL_STAGES 10

/* The Rust side (lib.rs) */
typedef struct SynaHandle SynaHandle;
enum { SYNA_IMAGE = 0, SYNA_RETRY = 1, SYNA_CANCELLED = 2, SYNA_ERROR = -1 };
enum { SYNA_STATUS_NEEDED = 1, SYNA_STATUS_PRESENT = 2 };
SynaHandle *syna_open (guint8 bus, guint8 address, char **error);
void syna_close (SynaHandle *handle);
gsize syna_image_size (void);
double syna_threshold (void);
int syna_capture (SynaHandle *handle,
                  int (*is_cancelled) (gpointer user),
                  void (*on_status) (gpointer user, int status),
                  gpointer user,
                  guint8 *image,
                  char **error);
guint8 *syna_template_encode (const guint8 *images, gsize count, gsize *len);
void syna_bytes_free (guint8 *bytes, gsize len);
double syna_match (const guint8 *template, gsize len, const guint8 *image, char **error);
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

/* Worker results for verify and identify: a template index, no match, or a
 * rejected placement */
#define SYNA_OUTCOME_NO_MATCH -1
#define SYNA_OUTCOME_RETRY -2

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

static GBytes *
print_template (FpPrint *print)
{
  g_autoptr(GVariant) data = NULL;
  gconstpointer bytes;
  gsize len;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE_BYTESTRING))
    return NULL;
  bytes = g_variant_get_fixed_array (data, &len, 1);
  return g_bytes_new (bytes, len);
}

/* Best-scoring template index at or above the threshold, or SYNA_OUTCOME_NO_MATCH */
static gint
best_match (GPtrArray *templates, const guint8 *image)
{
  gint best = SYNA_OUTCOME_NO_MATCH;
  double best_score = syna_threshold ();

  for (guint i = 0; i < templates->len; i++)
    {
      GBytes *template = g_ptr_array_index (templates, i);
      char *message = NULL;
      gsize len = 0;
      const guint8 *bytes = template ? g_bytes_get_data (template, &len) : NULL;
      double score = bytes ? syna_match (bytes, len, image, &message) : NAN;

      if (isnan (score))
        {
          fp_warn ("Skipping an unreadable template: %s", message ? message : "not ours");
          syna_string_free (message);
          continue;
        }
      fp_dbg ("Template %u scored %.3f (threshold %.3f)", i, score, syna_threshold ());
      if (score >= best_score)
        {
          best = i;
          best_score = score;
        }
    }
  return best;
}

/* Enroll */

static void
enroll_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  gsize size = syna_image_size ();
  g_autofree guint8 *image = g_malloc (size);
  g_autoptr(GByteArray) images = g_byte_array_new ();
  gint stages = 0;
  guint8 *encoded;
  gsize len = 0;
  GVariant *data;

  while (stages < SYNA_ENROLL_STAGES)
    {
      GError *error = NULL;
      int outcome = capture (self, image, &error);
      Report *report = g_new0 (Report, 1);

      if (error)
        {
          g_free (report);
          g_task_return_error (task, error);
          return;
        }
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

  encoded = syna_template_encode (images->data, stages, &len);
  if (!encoded)
    {
      g_task_return_error (task, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "Could not encode the template"));
      return;
    }
  data = g_variant_ref_sink (g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, encoded, len, 1));
  syna_bytes_free (encoded, len);
  g_task_return_pointer (task, data, (GDestroyNotify) g_variant_unref);
}

static void
enroll_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *device = FP_DEVICE (source);
  GError *error = NULL;
  g_autoptr(GVariant) data = g_task_propagate_pointer (G_TASK (result), &error);
  FpPrint *print = NULL;

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (error)
    {
      fpi_device_enroll_complete (device, NULL, error);
      return;
    }
  fpi_device_get_enroll_data (device, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  fpi_device_enroll_complete (device, g_object_ref (print), NULL);
}

static void
syna_enroll (FpDevice *device)
{
  GTask *task = g_task_new (device, NULL, enroll_done, NULL);

  g_atomic_int_set (&FPI_DEVICE_SYNA_00A2 (device)->cancelling, FALSE);
  g_task_run_in_thread (task, enroll_thread);
  g_object_unref (task);
}

/* Verify and identify: one placement, matched against one or more templates */

static void
match_thread (GTask *task, gpointer source, gpointer task_data, GCancellable *cancellable)
{
  FpiDeviceSyna00a2 *self = FPI_DEVICE_SYNA_00A2 (source);
  GPtrArray *templates = task_data;
  g_autofree guint8 *image = g_malloc (syna_image_size ());
  GError *error = NULL;
  int outcome = capture (self, image, &error);

  if (error)
    g_task_return_error (task, error);
  else if (outcome == SYNA_RETRY)
    g_task_return_int (task, SYNA_OUTCOME_RETRY);
  else
    g_task_return_int (task, best_match (templates, image));
}

static void
start_match (FpDevice *device, GPtrArray *prints, GAsyncReadyCallback done)
{
  GPtrArray *templates = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  GTask *task = g_task_new (device, NULL, done, NULL);

  for (guint i = 0; i < prints->len; i++)
    g_ptr_array_add (templates, print_template (g_ptr_array_index (prints, i)));
  g_atomic_int_set (&FPI_DEVICE_SYNA_00A2 (device)->cancelling, FALSE);
  g_task_set_task_data (task, templates, (GDestroyNotify) g_ptr_array_unref);
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

  fpi_device_get_verify_data (device, &print);
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
  dev_class->cancel = syna_cancel;
  /* list, delete and clear_storage stay NULL: fprintd stores the templates.
   * The TOD loader fills in the feature flags from these. */
}
