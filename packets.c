/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "packets.h"

/* Obscure the unique controller IDs in reports */
#define HIDE_DEVICE_IDS 0

void hexdump_bytes(const unsigned char *buf, int length) {
  for(int i = 0; i < length; i++){
    printf("%02x ", buf[i]);
  }
}

bool
parse_hmd_report (hmd_report_t *report, const unsigned char *buf, int size)
{
  if (buf[0] != 0x65)
    return false;

  if (size != 64 || size != sizeof (hmd_report_t))
    return false;

  *report = *(hmd_report_t *)(buf);

  return true;
}

void dump_hmd_report (hmd_report_t *report, const char endchar)
{
  printf ("const %u ts %10u mark %2x ",
      report->unknown_const1, report->timestamp, report->marker);

  for (int i = 0; i < 2; i++) {
    printf ("accel[%d] %5d %5d %5d gyro[%d] %5d %5d %5d unk %u mark %2x | ",
      i, report->samples[i].accel[0], report->samples[i].accel[1], report->samples[i].accel[2],
      i, report->samples[i].gyro[0], report->samples[i].gyro[1], report->samples[i].gyro[2],
      report->samples[i].unknown, report->samples[i].marker);
  }

  printf ("%2x frame_ts %10u ", report->unknown2, report->frame_timestamp);
  printf ("zero %d frame_id %5d zero %d", report->unknown_zero1, report->frame_id, report->unknown_zero2);

  printf ("%c", endchar);
}

bool
parse_controller_report (controller_report_t *report, const unsigned char *buf, int size)
{
  uint8_t avail;

  if (buf[0] != 0x67)
    return false;

  if (size != 62)
    return false;

  report->id = buf[0];
  report->device_id = *(uint64_t *)(buf + 1);
  report->data_len = buf[9];
  report->num_info = 0;
  report->extra_bytes_len = 0;
  report->flags = 0;
  memset (report->log, 0, sizeof (report->log));

#if HIDE_DEVICE_IDS
  // By default, obscure device IDs, since they are unique
  if (report->device_id)
    report->device_id |= 0xf00ff00ff0f00f0f;
#endif

  if (report->data_len < 4) {
    if (report->data_len != 0)
      fprintf (stderr, "Controller report with data len %u - please report it\n", report->data_len);
    return true; // No more to read
  }

  /* Advance the buffer pointer to the end of the common header.
   * We now have data_len bytes left to read
   */
  buf += 10;
  size -= 10;

  if (report->data_len > size) {
    fprintf (stderr, "Controller report with data len %u > packet size 62 - please report it\n", report->data_len);
    report->data_len = size;
  }

  avail = report->data_len;

  report->flags = buf[0];
  report->log[0] = buf[1];
  report->log[1] = buf[2];
  report->log[2] = buf[3];
  buf += 4;
  avail -= 4;

  /* While we have at least 2 bytes (type + at least 1 byte data), read a block */
  while (avail > 1 && report->num_info < sizeof(report->info) / sizeof(report->info[0])) {
    controller_info_block_t *info = report->info + report->num_info;
    size_t block_size = 0;
    info->block_id = buf[0];

    switch (info->block_id) {
      case RIFT_S_CTRL_MASK08:
      case RIFT_S_CTRL_BUTTONS:
      case RIFT_S_CTRL_FINGERS:
      case RIFT_S_CTRL_MASK0e:
        block_size = sizeof (controller_maskbyte_block_t);
        break;
      case RIFT_S_CTRL_TRIGGRIP:
        block_size = sizeof (controller_triggrip_block_t);
        break;
      case RIFT_S_CTRL_JOYSTICK:
        block_size = sizeof (controller_joystick_block_t);
        break;
      case RIFT_S_CTRL_CAPSENSE:
        block_size = sizeof (controller_capsense_block_t);
        break;
      case RIFT_S_CTRL_IMU:
        block_size = sizeof (controller_imu_block_t);
        break;
      default:
        break;
    }

    if (block_size == 0 || avail < block_size)
      break; /* Invalid block, or not enough data */

    memcpy (info->raw.data, buf, block_size);
    buf += block_size;
    avail -= block_size;
    report->num_info++;
  }

  if (avail > 0) {
    assert (avail < sizeof (report->extra_bytes));
    report->extra_bytes_len = avail;
    memcpy (report->extra_bytes, buf, avail);
  }

  return true;
}

#define PRINTABLE_CHAR(c) ((c) >= ' ' && (c) <= '~') ? (c) : '.'

void dump_controller_report (controller_report_t *report, const char endchar)
{
  printf ("device %16lx len %02x flags %02x log %c%c%c | ",
      report->device_id, report->data_len, report->flags,
      PRINTABLE_CHAR(report->log[0]), PRINTABLE_CHAR(report->log[1]), PRINTABLE_CHAR(report->log[2]));

  for (int i = 0; i < report->num_info; i++) {
    controller_info_block_t *info = report->info + i;

    switch (info->block_id) {
      case RIFT_S_CTRL_MASK08:
        printf ("mask08 %02x | ", info->maskbyte.val);
        break;
      case RIFT_S_CTRL_BUTTONS:
        printf ("Buttons mask %02x | ", info->maskbyte.val);
        break;
      case RIFT_S_CTRL_FINGERS:
        printf ("Fingers mask %02x | ", info->maskbyte.val);
        break;
      case RIFT_S_CTRL_MASK0e:
        printf ("mask0e %02x | ", info->maskbyte.val);
        break;
      case RIFT_S_CTRL_TRIGGRIP:
        printf ("Trigger/Grip ");
        hexdump_bytes(info->triggrip.vals, sizeof (info->triggrip.vals));
        printf ("| ");
        break;
      case RIFT_S_CTRL_JOYSTICK:
        printf ("Joystick %08x", info->joystick.val);
        printf ("| ");
        break;
      case RIFT_S_CTRL_CAPSENSE:
        printf ("capsense a/x %u b/y %u joy %u trig %u | ",
            info->capsense.a_x, info->capsense.b_y,
            info->capsense.joystick, info->capsense.trigger);
        break;
      case RIFT_S_CTRL_IMU:
        printf ("IMU ts %8u v2 %x accel %6d %6d %6d gyro %6d %6d %6d | ",
            info->imu.timestamp, info->imu.unknown_varying2,
            info->imu.accel[0], info->imu.accel[1], info->imu.accel[2],
            info->imu.gyro[0], info->imu.gyro[1], info->imu.gyro[2]);
        break;
      default:
        fprintf (stderr, "Oops - invalid info block with ID %02x\n", info->block_id);
        assert ("Should not be reached!" == NULL);
        break;
    }
  }

  if (report->extra_bytes_len > 0) {
    printf ("extra ");
    hexdump_bytes(report->extra_bytes, report->extra_bytes_len);
  }
  printf ("%c", endchar);
}
