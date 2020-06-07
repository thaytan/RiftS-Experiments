/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */
#ifndef __STATE_H__
#define __STATE_H__

#include <stdint.h>

#define MAX_LOG_SIZE 1024

typedef struct {
  uint64_t device_id;
  uint32_t device_type;

  /* 0x04 = new log line
   * 0x02 = parity bit, toggles each line when receiving log chars 
   * other bits, unknown */
  uint8_t log_flags;
  int log_bytes;
  uint8_t log[MAX_LOG_SIZE];

  uint32_t imu_timestamp;
  uint16_t imu_unknown_varying2;
  int16_t accel[3];
  int16_t gyro[3];

  /* 0x8, 0x0c 0x0d or 0xe block */
  uint8_t mask08;
  uint8_t buttons;
  uint8_t fingers;
  uint8_t mask0e;

  uint16_t trigger;
  uint16_t grip;

  int16_t joystick_x;
  int16_t joystick_y;

  uint8_t capsense_a_x;
  uint8_t capsense_b_y;
  uint8_t capsense_joystick;
  uint8_t capsense_trigger;

  uint8_t extra_bytes_len;
  uint8_t extra_bytes[48];
} controller_state_t;

#endif
