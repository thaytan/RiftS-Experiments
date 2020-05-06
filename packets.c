/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */
#include <stdio.h>

#include "packets.h"

static void hexdump(const unsigned char *buf, int length) {
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
  printf ("const %u ts %6u zero %u ",
      report->unknown_const1, report->timestamp, report->unknown_const_zero);

  for (int i = 0; i < 2; i++) {
    printf ("accel[%d] %5d %5d %5d gyro[%d] %5d %5d %5d unknown ",
      i, report->samples[i].accel[0], report->samples[i].accel[1], report->samples[i].accel[2],
      i, report->samples[i].gyro[0], report->samples[i].gyro[1], report->samples[i].gyro[2]);
    hexdump (report->samples[i].unknown1, sizeof(report->samples[i].unknown1));
  }

  hexdump (report->unknown2, sizeof(report->unknown2));

  printf ("%c", endchar);
}

bool
parse_controller_report (controller_report_t *report, const unsigned char *buf, int size)
{

  if (buf[0] != 0x67)
    return false;

  if (size != 62 || size != sizeof (controller_report_t))
    return false;

  *report = *(controller_report_t *)(buf);

  return true;
}

void dump_controller_report (controller_report_t *report, const char endchar)
{
  printf ("device %08lx %u %u ts %10lu accel %6d %6d %6d gyro %6d %6d %6d unknown1 %u button %x unknown2 ",
      report->device_id, report->unknown_varying1, report->unknown_const1,
      report->timestamp, report->accel[0], report->accel[1], report->accel[2],
      report->gyro[0], report->gyro[1], report->gyro[2], report->unknown1, report->button_mask);
  hexdump (report->unknown2, 13);
  printf (" js cap %5u trigger cap %5u unknown3 ",
      report->joystick_capsense, report->trigger_capsense);
  hexdump (report->unknown3, 3);
  printf (" button cap ");
  hexdump (report->button_capsense_maybe, 6);
  printf (" end %u%c", report->unknown_const2, endchar);
}
