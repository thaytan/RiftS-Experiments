/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */

#ifndef __PACKETS_H__
#define __PACKETS_H__

#include <stdint.h>
#include <stdbool.h>

typedef enum {
  RIFT_S_CTRL_BTN08 = 0x08,
  RIFT_S_CTRL_BTN1 = 0x0c,
  RIFT_S_CTRL_BTN2 = 0x0d,
  RIFT_S_CTRL_BTN0e = 0x0e,
  RIFT_S_CTRL_UNKNOWN_1b = 0x1b,
  RIFT_S_CTRL_CAPSENSE = 0x22,
  RIFT_S_CTRL_UNKNOWN_27 = 0x27,
  RIFT_S_CTRL_IMU = 0x91
} rift_s_controller_block_id_t;

typedef struct {
  uint8_t id;

  uint32_t timestamp;
  uint16_t unknown_varying2;

  int16_t accel[3];
  int16_t gyro[3];
}  __attribute__((aligned(1), packed)) controller_imu_block_t;

typedef struct {
  /* 0x0c or 0x0d block */
  uint8_t id;

  uint8_t mask;
}  __attribute__((aligned(1), packed)) controller_button_block_t;

typedef struct {
  /* 0x1b block */
  uint8_t id;

  uint8_t vals[3];
}  __attribute__((aligned(1), packed)) controller_unknown1b_block_t;

typedef struct {
  /* 0x22 block */
  uint8_t id;

  uint8_t vals[4];
}  __attribute__((aligned(1), packed)) controller_capsense_block_t;

typedef struct {
  /* 0x27 block */
  uint8_t id;

  uint8_t vals[4];
}  __attribute__((aligned(1), packed)) controller_unknown27_block_t;

typedef struct {
  uint8_t data[19];
}  __attribute__((aligned(1), packed)) controller_raw_block_t;

typedef union {
  uint8_t block_id;
  controller_imu_block_t imu;
  controller_button_block_t button;
  controller_unknown1b_block_t unknown1b;
  controller_capsense_block_t capsense;
  controller_unknown27_block_t unknown27;
  controller_raw_block_t raw;
}  __attribute__((aligned(1), packed)) controller_info_block_t;

typedef struct {
  uint8_t id;

  uint64_t device_id;

  /* Length of the data block, which contains variable length entries
   * If this is < 4, then the flags and log aren't valid. */
  uint8_t data_len;

  /* 0x04 = new log line
   * 0x02 = parity bit, toggles each line when receiving log chars 
   * other bits, unknown */
  uint8_t flags;
  // Contains up to 3 bytes of debug log chars
  uint8_t log[3];

  uint8_t num_info;
  controller_info_block_t info[8];

  uint8_t extra_bytes_len;
  uint8_t extra_bytes[48];
} controller_report_t;

typedef struct {
  int16_t accel[3];
  int16_t gyro[3];

  uint16_t delta_ts;
  uint8_t marker;
} __attribute__((aligned(1), packed)) hmd_imu_sample_t;

typedef struct {
  uint8_t id;
  uint16_t unknown_const1;

  uint32_t timestamp;

  uint8_t marker;

  hmd_imu_sample_t samples[3];

  uint8_t unknown2;
  uint32_t timestamp2;

  int16_t unknown3[3];
} __attribute__((aligned(1), packed)) hmd_report_t;

void hexdump_bytes(const unsigned char *buf, int length);

bool parse_hmd_report (hmd_report_t *report, const unsigned char *buf, int size);
void dump_hmd_report (hmd_report_t *report, const char endchar);

bool parse_controller_report (controller_report_t *report, const unsigned char *buf, int size);
void dump_controller_report (controller_report_t *report, const char endchar);

#endif
