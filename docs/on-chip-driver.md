# On-chip matching driver: design (draft, 2026-10-19)

The TOD driver today keeps templates on the host and matches them with the
correlation matcher (`src/matcher.rs`). That matcher fails across days. The
sensor's own matcher works: a template built on the host from four
same-session placements (`src/moh.rs`), stored with `0x47`, matched 8/8 of
the right middle and 0/3 of other fingers (2026-10-19, record 9). This
document plans the switch to device-stored prints. Statements marked
*(untested)* need a hardware experiment first.

## What is verified

- Template building: `moh::template` is byte-identical to python-validity's
  native pipeline (131 frames, two stored envelopes).
- Storing: `db_write_enable` (0x06 blob), `0x47` (type 6, storage StgWindsor,
  trailer `00`), then `0x1a` commit. Done twice, both OK.
- Matching: an identify-mode scan, `0x5e 02 ff` with storage 0 and user 0
  ("any"), then the event on EP 0x83 (`03…` recognised, `04…` not), then
  `0x60` for the result and `0x62` to clean up.
- **The result's 32-byte hash is the template's TemplateId** (`moh::template_id`
  of the WS body). Record 9's TID prefix `0ade2a7f0fa2fdfd` equals the
  `hash_prefix` of its matches. So a match maps exactly to one template, and
  the driver knows each template's TID when it builds it.
- Not verified: whether a template still matches on later days. Record 8,
  built from 2026-10-18 frames, did not match on 2026-10-19. Experiment x1
  (plan rev 20) tests record 9 on a later day. Every enrollment decision below
  depends on that result.

## How fprintd uses device storage (fprintd 1.94.5, `src/device.c`)

libfprint sets `STORAGE` when a driver has `delete` and (`list` or
`clear_storage`). fprintd then does the following:

1. **Before every enrollment**, it identifies against all host prints of all
   users, which costs one extra touch:
   - A gallery match ends the enrollment as `enroll-duplicate`.
   - If the driver reports a device print that is **not** in the gallery,
     fprintd **deletes it from the device** and continues.
2. **On a failed match** (first time per claim), it lists the device prints
   and deletes the *host* records the device doesn't list.
3. **On `DATA_FULL`** during enroll, it lists the device prints and deletes
   the oldest one that it doesn't know, then retries.
4. **With `STORAGE` but no `STORAGE_LIST`**, it calls `clear_storage` before
   the first enrollment.
5. On delete, it calls `delete` for each of the user's host prints, and for
   one finger before re-enrolling it.

Consequence: anything the driver lists or reports, fprintd may delete.
**The driver must never list or report a record that Linux didn't create**:
the Windows user's finger (record 6), or the test records 8 and 9 under the
same user. `clear_storage` stays unimplemented.

## Ownership: one chip user record per Linux user

- Each Linux user gets their own user record (type 5 under StgWindsor). Its
  identity is python-validity's default SID
  `S-1-5-21-111111111-1111111111-1111111111-<uid>`, as type-3 identity bytes
  zero-padded to 0x4c (`identity_to_bytes`). It is created at the user's first
  enrollment. python-validity does the same, so the two stay interoperable.
- **Linux-owned** means: a user record whose SID has that prefix. Every
  operation below checks this first. Other user records and their fingers are
  never listed, reported, matched as a success, or deleted.
- Considered and rejected:
  - Filing under the existing Windows user record 5 mixes ownership with a
    Windows account (most likely the previous owner's), and one bad delete
    could remove its finger.
  - One shared "Linux" record leaves several users with the same finger
    subtype under one record, which nothing has tested.
- Subtype = WinBio finger position, from libfprint's finger:
  `RIGHT_THUMB..RIGHT_LITTLE` (6..10) → 1..5, and `LEFT_THUMB..LEFT_LITTLE`
  (1..5) → 6..10. fprintd refuses to enroll `FP_FINGER_UNKNOWN`, so there is
  no need for the "unspecified" range 0xf5..0xfe.

## Prints

- `FPI_PRINT_RAW`, `fpi_print_set_device_stored (TRUE)`. The fpi-data is a
  GVariant `(qqqay)`: the user record, the finger record, the subtype, and
  the 32-byte TID.
- `fp_print_equal` compares the type, driver, device id and `g_variant_equal`
  of that data. Every field can be read back from the chip, so `list` rebuilds
  prints that compare equal to the enrolled ones.
- The host holds **no biometric data**: no images and no envelope, only
  identifiers.
- The device id stays libfprint's default "0" unless a stable per-sensor id
  is found (open question 7).

## Operations

All of these run in the existing GTask workers on the open session.

| vfunc | What it does | DB writes |
|---|---|---|
| open / close | As now: session, calibration (no change) | none |
| enroll | Enroll-mode touches (stages; a frame whose pool is under 250 is a retry), `moh::template` with the subtype, then: find the Linux user (`0x4a` by identity), or **create it**; check free space (else `DATA_FULL`); **store the finger**; read back its record and TID | user record (first enrollment only), finger record |
| verify | Identify-mode touch (held-finger skip, stall restart), chip match, `0x60` result. Match only if recognised **and** the TID equals the print's. A rejected scan is a retry. | none |
| identify | Same scan and match. Report the gallery print with that TID. If the TID is a Linux-owned record that isn't in the gallery, report it as the device print (fprintd's garbage collection). A foreign TID, or not recognised, reports no match. | none |
| list | StgWindsor → Linux-owned users → fingers → `0x49` value → TID → prints (finger from the subtype, username from the uid) | none |
| delete | Re-read the record. Refuse unless it is Linux-owned and its TID matches the print. Then **delete the finger**, and the user record once it is empty. | finger record (and user record) |
| clear_storage | not implemented, on purpose | — |

Matching scope: `0x5e` with user 0 searches every template. A foreign record
can then win over the Linux one and turn a genuine touch into a no-match. Two
fixes:

- `0x5e` has u16 storage and user fields (python-validity sends 0, "any").
  Restricting verify to the print's user record would fix it *(untested)*.
- Until that is tested: delete the test records 8 and 9 (with the user's OK)
  before Linux enrollments go live. Record 6 never matched any of the user's
  fingers, so it doesn't compete.

## Which steps write to the template database

Writes only ever happen inside an enrollment or deletion that the user starts
(fprintd-enroll, GNOME Settings, fprintd-delete):

1. Creating a Linux user record: once per Linux user, at their first
   enrollment.
2. Storing a finger: each enrollment, about 23 KB of partition 4.
3. Deleting a finger: each deletion, and before re-enrolling the same finger.
4. Deleting an empty Linux user record.

Each write follows a fixed sequence:

- Read first: free space, the StgWindsor storage, and the parent's existence
  and ownership.
- Then the writes: `db_write_enable`, the write command, `0x1a`.
- Then read again to confirm.

Verify, identify and list never write. The partition currently has 452 KB
free, room for about 19 templates.

## Open questions, each a separate experiment

1. *(no write)* Cross-day match of record 9: x1, plan rev 20.
2. *(no write)* Does `0x5e`'s user field restrict matching? Match a right-middle
   touch with user = 5 (expect recognised), then with a user id that doesn't
   exist (expect not recognised, or an error status).
3. *(write, needs OK)* Create one Linux user record. Then check that `0x4a`
   finds it by identity and that the StgWindsor user list shows it.
4. *(write, needs OK)* Delete test record 8 with `0x48`. Does it need
   `db_write_enable` and a commit? python-validity sends `0x48` alone. Check
   with `0x45`/`0x46` afterwards.
5. Enrollment coverage, if question 1 fails:
   - more touches, and a better choice of the four frames;
   - or two templates per finger from different placements (the chip matches
     any of them);
   - or porting the DLL's cross-frame consensus (EnrollmentUpdate).
6. Touches per enrollment: python-validity uses 6, keeping the best 4. With
   fprintd's duplicate check, a Linux enrollment costs one more touch.
7. A stable device id from the chip (sensor ID or flash JID), so that prints
   don't carry "0".
8. Suspend during an on-chip action: libfprint completes it with
   `NOT_SUPPORTED` (no suspend vfunc). Confirm that fprintd recovers.

## Implementation steps (after questions 1 to 4)

1. Library `chip` module:
   - identity bytes and Linux ownership;
   - find or create a user, store, delete;
   - list fingers with their TIDs;
   - match, with an optional user restriction (moving `chip_match` out of
     `main.rs`).
2. CLI subcommands for each operation, with writes gated by `--confirm`, for
   panel experiments.
3. TOD:
   - device-stored prints with the vfuncs above;
   - identify-mode scans for verify and identify;
   - drop the host correlation matcher from the driver.

   No production enrollments exist yet: only the test harness's `print-a.fp`
   and `print-b.fp`, which become incompatible.
4. Panel validation:
   - enroll, verify, identify;
   - re-enroll the same finger;
   - delete;
   - the duplicate check;
   - a cross-day verify.
