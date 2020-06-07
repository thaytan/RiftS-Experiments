/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */

#ifndef __PACKETS_H__
#define __PACKETS_H__

#include <stdint.h>
#include <stdbool.h>

#define RIFT_S_BUTTON_A 0x01
#define RIFT_S_BUTTON_B 0x02
#define RIFT_S_BUTTON_STICK 0x04
#define RIFT_S_BUTTON_OCULUS 0x08

#define RIFT_S_BUTTON_UNKNWON 0x10 // Unknown mask value seen sometimes. Low battery?

#define RIFT_S_FINGER_A_X_STRONG 0x01
#define RIFT_S_FINGER_B_Y_STRONG 0x02
#define RIFT_S_FINGER_STICK_STRONG 0x04
#define RIFT_S_FINGER_TRIGGER_STRONG 0x08
#define RIFT_S_FINGER_A_X_WEAK 0x10
#define RIFT_S_FINGER_B_Y_WEAK 0x20
#define RIFT_S_FINGER_STICK_WEAK 0x40
#define RIFT_S_FINGER_TRIGGER_WEAK 0x80

typedef enum {
  RIFT_S_CTRL_MASK08 = 0x08,    /* Unknown. Vals seen 0x28, 0x0a, 0x32, 0x46, 0x00... */
  RIFT_S_CTRL_BUTTONS = 0x0c,   /* Button states */
  RIFT_S_CTRL_FINGERS = 0x0d,   /* Finger positions */
  RIFT_S_CTRL_MASK0e = 0x0e,    /* Unknown. Only seen 0x00 */
  RIFT_S_CTRL_TRIGGRIP = 0x1b,  /* Trigger + Grip */
  RIFT_S_CTRL_JOYSTICK = 0x22,  /* Joystick X/Y */
  RIFT_S_CTRL_CAPSENSE = 0x27,  /* Capsense */
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
  /* 0x08, 0x0c, 0x0d or 0x0e block */
  uint8_t id;

  uint8_t val;
}  __attribute__((aligned(1), packed)) controller_maskbyte_block_t;

typedef struct {
  /* 0x1b trigger/grip block */
  uint8_t id;
  uint8_t vals[3];
}  __attribute__((aligned(1), packed)) controller_triggrip_block_t;

typedef struct {
  /* 0x22 joystick axes block */
  uint8_t id;
  uint32_t val;
}  __attribute__((aligned(1), packed)) controller_joystick_block_t;

typedef struct {
  /* 0x27 - capsense block */
  uint8_t id;

  uint8_t a_x;
  uint8_t b_y;
  uint8_t joystick;
  uint8_t trigger;
}  __attribute__((aligned(1), packed)) controller_capsense_block_t;

typedef struct {
  uint8_t data[19];
}  __attribute__((aligned(1), packed)) controller_raw_block_t;

typedef union {
  uint8_t block_id;
  controller_imu_block_t imu;
  controller_maskbyte_block_t maskbyte;
  controller_triggrip_block_t triggrip;
  controller_joystick_block_t joystick;
  controller_capsense_block_t capsense;
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
  uint8_t marker; /* 0x80 = invalid, other values... not sure. Time offset? */
  int16_t accel[3];
  int16_t gyro[3];

  /* For a while I thought this was a time delta, but the values
   * don't really make sense. They're sometimes ~2000, sometimes around 4000-4400,
   * and seem to gradually increase the longer the headset is running. Is it temperature?
   * If so, it's very noisy */
  int16_t temperature;
} __attribute__((aligned(1), packed)) hmd_imu_sample_t;

typedef struct {
  uint8_t id;
  uint16_t unknown_const1;

  uint32_t timestamp;

  hmd_imu_sample_t samples[3];

  uint8_t marker;
  uint8_t unknown2;

  /* Frame timestamp and ID increment when the screen is running,
   * every 12.5 ms (80Hz) */
  uint32_t frame_timestamp;
  int16_t unknown_zero1;
  int16_t frame_id;
  int16_t unknown_zero2;
} __attribute__((aligned(1), packed)) hmd_report_t;

/* Packet read from endpoint 11 (0x0b) */
typedef struct {
    uint8_t cmd;
    uint8_t seqnum;
    uint8_t busy_flag;
    uint8_t response_bytes[197];
} __attribute__((aligned(1), packed)) hmd_radio_response_t;

/* Struct for sending radio commands to 0x12 / 0x13 */
typedef struct {
    uint8_t cmd;
    uint64_t device_id;
    uint8_t cmd_bytes[52];
} __attribute__((aligned(1), packed)) hmd_radio_command_t;

/* Read using report 9 */
typedef struct {
		uint8_t cmd;
		uint32_t imu_hz;
		float gyro_scale; /* Gyro = reading / 32768 * gyro_scale */
		float accel_scale; /* Accel = reading * g / accel_scale */
		float temperature_scale; /* Temperature = reading / scale + offset */
		float temperature_offset;
} __attribute__((aligned(1), packed)) rift_s_imu_config_t;

typedef enum {
    RIFT_S_DEVICE_TYPE_UNKNOWN = 0,
    RIFT_S_DEVICE_LEFT_CONTROLLER = 0x13001101,
    RIFT_S_DEVICE_RIGHT_CONTROLLER = 0x13011101,
} rift_s_device_type;

typedef struct {
  uint64_t device_id;
  uint32_t device_type;
} __attribute__((aligned(1), packed)) rift_s_device_type_record_t;

void hexdump_bytes(const unsigned char *buf, int length);

bool parse_hmd_report (hmd_report_t *report, const unsigned char *buf, int size);
void dump_hmd_report (hmd_report_t *report, const char endchar);

bool parse_controller_report (controller_report_t *report, const unsigned char *buf, int size);
void dump_controller_report (controller_report_t *report, const char endchar);

#endif
