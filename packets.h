/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */

#ifndef __PACKETS_H__
#define __PACKETS_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  uint8_t id;

  uint64_t device_id;
  uint16_t unknown_varying1;
  uint16_t unknown_const1;

  uint64_t timestamp;

  int16_t accel[3];
  int16_t gyro[3];

  uint8_t unknown1;

  /* There seems to be some button
   * press info here */
  uint8_t button_mask;
  uint8_t unknown2[13];

  uint16_t joystick_capsense;
  uint16_t trigger_capsense;

  uint8_t unknown3[3];

  uint8_t button_capsense_maybe[6];

  uint8_t unknown_const2;
} __attribute__((aligned(1), packed)) controller_report_t;

typedef struct {
  int16_t accel[3];
  int16_t gyro[3];

  uint8_t unknown1[3];
} __attribute__((aligned(1), packed)) hmd_imu_sample_t;

typedef struct {
  uint8_t id;
  uint16_t unknown_const1;

  uint32_t timestamp;

  uint8_t unknown_const_zero;
  hmd_imu_sample_t samples[2];

  uint8_t unknown2[26];
} __attribute__((aligned(1), packed)) hmd_report_t;

bool parse_hmd_report (hmd_report_t *report, const unsigned char *buf, int size);
void dump_hmd_report (hmd_report_t *report, const char endchar);

bool parse_controller_report (controller_report_t *report, const unsigned char *buf, int size);
void dump_controller_report (controller_report_t *report, const char endchar);

#endif
