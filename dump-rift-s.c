/*
 * Copyright 2019 Lucas Teske <lucas@teske.com.br>
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 */
#include <stdio.h>
#include <hidapi/hidapi.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include "packets.h"

#include "controller_fw_commands.h"

#define FEATURE_BUFFER_SIZE 64

#define KEEPALIVE_INTERVAL_MS 1000
#define CAMERA_REPORT_INTERVAL_MS 1000

#define MAX_CONTROLLERS 2

typedef struct {
  uint64_t device_id;
  bool finished_fw_read;
  bool command_result_pending;
  int read_command_idx;
} controller_fw_state_t;

static int num_controllers = 0;
static controller_fw_state_t controllers[MAX_CONTROLLERS];
static controller_fw_state_t *cur_controller_read = NULL;
int last_radio_seqnum = -1;

bool shutdown_and_exit = false;
bool dump_all = true;
bool dump_fw = false;
bool dump_controllers = false;
bool dump_hmd = false;
bool dump_parsed = false;
bool dump_singleline = false;
bool read_controller_fw = false;
bool display_on = false;

static int sleep_us (uint64_t usec);

static void
sigint_handler (int signum)
{
    shutdown_and_exit = true;
}

static void printBuffer(const char *label, const unsigned char *buf, int length) {
  int indent;
  char ascii[17];

  if (label)
    indent = strlen (label) + 2;
  printf("%s: ", label);

	ascii[16] = '\0';
  for(int i = 0; i < length; i++){
    printf("%02x ", buf[i]);

    if (buf[i] >= ' ' && buf[i] <= '~')
			ascii[i % 16] = buf[i];
		else
			ascii[i % 16] = '.';

    if((i % 16) == 15 || (i+1) == length) {
       if ((i % 16) < 15) {
        int remain = 15 - (i%16);
         ascii[(i+1) % 16] = '\0';
         /* Pad the hex dump out to 48 chars */
         printf("%*s", 3*remain, " ");
       }
       printf("| %s", ascii);

       if ((i+1) != length)
         printf("\n%*s", indent, " ");
    }
  }
  printf("\n");
}

static void clear_buff(unsigned char *buff, int length) {
  for (int i = 0; i < length; i++) {
    buff[i] = 0x00;
  }
}

static int get_report(hid_device *hid, char id, unsigned char *buff, int length) {
  buff[0] = id;
  clear_buff(&buff[1], length-1);
  return hid_get_feature_report(hid, buff, length);
}

static int
read_one_fw_block (hid_device *dev, uint8_t block_id, uint32_t pos, uint8_t read_len, uint8_t *buf)
{
  unsigned char req[64] = { 0x4a, 0x00, };
  int ret, loops = 0;
  bool send_req = true;

  req[2] = block_id;

  do {
    if (send_req) {
      /* FIXME: Little-endian code: */
      * (uint32_t *)(req + 3) = pos;
      req[7] = read_len;
      ret = hid_send_feature_report(dev, req, 64);
      if (ret < 0) {
        printf ("Report 74 SET failed\n");
        return ret;
      }
    }

    ret = get_report(dev, 0x4A, buf, 64);
    if (ret < 0) {
      printf ("Report 74 GET failed\n");
      return ret;
    }
    /* Loop until the result matches the address we asked for and
     * the 2nd byte == 0x00 (0x1 = busy or req ignored?), or 20 attempts have passed */
    if (memcmp (req, buf, 7) == 0)
      break;

    /* Or if the 2nd byte of the return result is 0x1, the read is being processed,
     * don't send the req again. If it's 0x00, we seem to need to re-send the request  */
    send_req = (buf[1] == 0x00);

    sleep_us (2000);
  } while (loops++ < 20);

  if (loops > 20)
    return -1;

  return ret;
}

static int
dump_fw_block (hid_device *dev, uint8_t block_id)
{
  char label[64];
  uint32_t pos = 0x00, block_len;
  unsigned char buf[64] = { 0x4a, 0x00, };
  unsigned char *outbuf;
  size_t total_read = 0;
  uint64_t checksum;
  int ret;

  ret = read_one_fw_block (dev, block_id, 0, 0xC, buf);
  if (ret < 0) {
    printf ("Failed to read fw block %02x header\n", block_id);
    return ret;
  }

  /* The block header is 12 bytes. 8 byte checksum, 4 byte size? */
  checksum = *(uint64_t *)(buf + 8);
  block_len = *(uint32_t *)(buf + 16);

  if (block_len < 0xC || block_len == 0xFFFFFFFF)
    return 0; /* Invalid block */

  printf ("FW Block %02x Header. Checksum(?) %08lx len %d\n", block_id, checksum, block_len);

  /* Copy the contents of the fw block, minus the header */
  outbuf = malloc (block_len);
  total_read = 0x0;

  for (pos = 0x0; pos < block_len; pos += 56) {
    uint8_t read_len = 56;
    if (pos + read_len > block_len)
      read_len = block_len - pos;

    ret = read_one_fw_block (dev, block_id, pos + 0xC, read_len, buf);
    if (ret < 0) {
      printf ("Failed to read fw block %02x at pos 0x%08x len %d\n", block_id, pos, read_len);
      break;
    }
    memcpy (outbuf + total_read, buf + 8, read_len);
    total_read += read_len;
  }

  if (total_read > 0) {
    if (total_read < block_len) {
      printf ("Short FW read - only read %lu bytes of %u\n",
         total_read, block_len);
    }
    sprintf (label, "FW Block %02x", block_id);
    if (outbuf[0] == '{' && outbuf[total_read-2] == '}' && outbuf[total_read-1] == 0)
      printf ("%s\n", outbuf); // Dump JSON string
    else
      printBuffer(label, outbuf, total_read);
  }

  free (outbuf);

  return ret;
}

static void
send_keepalive (hid_device *hid)
{
  /* HID report 147 (0x93) 0xbb8 = 3000ms timeout, sent every 1000ms */
  unsigned char buf[6] = { 0x93, 0x01, 0xb8, 0x0b, 0x00, 0x00 };
  hid_send_feature_report(hid, buf, 6);
}

static void
send_camera_report (hid_device *hid, bool enable, bool radio_sync_bit)
{
/*
 *   05 O1 O2 P1 P1 P2 P2 P3 P3 P4 P4 P5 P5 E1 E1 E3
 *   E4 E5 U1 U2 U3 A1 A1 A1 A1 A2 A2 A2 A2 A3 A3 A3
 *   A3 A4 A4 A4 A4 A5 A5 A5 A5
 *
 *   O1 = Camera stream on (0x00 = off, 0x1 = on)
 *   O2 = Radio Sync maybe?
 *   Px = Vertical offset / position of camera x passthrough view
 *   Ex = Exposure of camera x passthrough view
 *   Ax = ? of camera x. 4 byte LE, Always seems to take values 0x3f0-0x4ff
 *        but I can't see the effect on the image
 *   U1U2U3 = 26 00 40 always?
 */
  unsigned char buf[41] = {
#if 0
    0x05, 0x01, 0x01, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xf0, 0xf0, 0xf0,
    0xf0, 0xf0, 0x26, 0x00, 0x40, 0x7a, 0x04, 0x00, 0x00, 0xa7, 0x04, 0x00, 0x00, 0xa7, 0x04, 0x00,
    0x00, 0xa5, 0x04, 0x00, 0x00, 0xa8, 0x04, 0x00, 0x00
#else
    0x05, 0x01, 0x01, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xb3, 0x36, 0xf0, 0xf0, 0xf0,
    0xf0, 0xf0, 0x26, 0x00, 0x40, 0x7a, 0x04, 0x00, 0x00, 0xa7, 0x04, 0x00, 0x00, 0xa7, 0x04, 0x00,
    0x00, 0xa5, 0x04, 0x00, 0x00, 0xa8, 0x04, 0x00, 0x00
#endif
  };

  buf[1] = enable ? 0x1 : 0x0;
  buf[2] = radio_sync_bit ? 0x1 : 0x0;

  hid_send_feature_report(hid, buf, 41);
}

static int
set_screen_state (hid_device *hid, bool enable)
{
  uint8_t buf[2];

  // Enable/disable LCD screen
  buf[0] = 0x08;
  buf[1] = enable ? 0x01 : 0;
  return hid_send_feature_report(hid, buf, 2);
}

#if 0
/* Report 18/19 are for talking to the controllers,
 * they start with the same 8-byte device ID as the
 * controller reports */
static void
send_report18 (hid_device *hid) {
  unsigned char buf1[61] = {
    0x12, 0x74, 0x1f, 0x62, 0xec, 0xa4, 0x7c, 0x1b, 0xd2, 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x00, 0x00,
    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  hid_send_feature_report(hid, buf1, 61);
}

static void
send_report19 (hid_device *hid) {
  static bool parity = false;

  unsigned char buf1[61] = {
    0x13, 0x74, 0x1f, 0x62, 0xec, 0xa4, 0x7c, 0x1b, 0xd2, 0x97, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  unsigned char buf2[61] = {
    0x13, 0x74, 0x1f, 0x62, 0xec, 0xa4, 0x7c, 0x1b, 0xd2, 0x22, 0x20, 0xe8, 0x03, 0xf2, 0x34, 0x00,
    0x00, 0x1b, 0x40, 0x03, 0xa3, 0x81, 0xad, 0xe7, 0x0f, 0x69, 0x00, 0x2f, 0xa9, 0xd0, 0x93, 0x07,
    0x0e, 0x68, 0x08, 0xbf, 0x4b, 0x69, 0x0f, 0x60, 0x18, 0xbf, 0x00, 0x23, 0xa6, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  /* Alternate sending buf1 and buf2 to see what happens */
  if (parity)
    hid_send_feature_report(hid, buf1, 61);
  else
    hid_send_feature_report(hid, buf2, 61);
}
#endif

static int get_radio_response_report (hid_device *hid, hmd_radio_response_t *radio_response)
{
   int ret = get_report(hid, 0xb, (unsigned char *)(radio_response), sizeof(hmd_radio_response_t));
   return ret;
}

static void
update_controller_fw_read(hid_device *hid)
{
    if (cur_controller_read == NULL && num_controllers > 0) {
      /* No firmware read currently in progress, check for a controller
       * we haven't finished reading yet */
      controller_fw_state_t *ctrl = NULL;
      int i;

      for (i = 0; i < num_controllers; i++) {
        if (controllers[i].finished_fw_read == false) {
          ctrl = controllers + i;
          break;
        }
      }

      if (ctrl != NULL) {
          printf ("Starting FW read on controller 0x%08lx\n", ctrl->device_id);
          if (last_radio_seqnum < 0) {
              /* Before the first firmware read, we need to sync up the sequence number
               * first */
              hmd_radio_response_t radio_response;

              if (get_radio_response_report (hid, &radio_response) < 3 ||
                  radio_response.busy_flag != 0x00) {
                printf ("Radio busy during initial seqnum read\n");
                return;
              }

              last_radio_seqnum = radio_response.seqnum;
              printf ("Got initial seqnum %d\n", radio_response.seqnum);
          }

          cur_controller_read = ctrl;
      }
    }

    /* Nothing to read right now */
    if (cur_controller_read == NULL)
        return;

    /* We are currently reading a controller firmware. See if we need to issue a new
     * read command */
    bool read_another = false;
    do {
      if (cur_controller_read->command_result_pending == false) {
        riftS_fw_command_t *next_command = riftS_fw_commands + cur_controller_read->read_command_idx;
        hmd_radio_command_t read_command;

        memset (&read_command, 0, sizeof (read_command));
        read_command.cmd = next_command->cmd;
        read_command.device_id = cur_controller_read->device_id;
        memcpy (read_command.cmd_bytes, next_command->cmd_bytes, sizeof (next_command->cmd_bytes));

        hid_send_feature_report(hid, (unsigned char *)(&read_command), sizeof(read_command));
        cur_controller_read->command_result_pending = true;
        printBuffer("ControllerFWSend", (unsigned char *)(&read_command), sizeof(read_command));
      }

      /* There's a command result pending, poll the radio response until it's complete */
      hmd_radio_response_t radio_response;

      /* The radio response is ready when the busy flag has cleared, and the seqnum
       * has incremented */
      int ret = get_radio_response_report (hid, &radio_response);
      assert (ret > 2);
      if (radio_response.busy_flag != 0x00 || radio_response.seqnum == last_radio_seqnum) {
        if (radio_response.busy_flag)
          last_radio_seqnum = radio_response.seqnum;
        return;
      }

      /* We have the controller response! */
      assert (ret <= sizeof(radio_response));

      cur_controller_read->command_result_pending = false;
      // printf("ControllerFWReply device %08lx len %d\n", cur_controller_read->device_id, ret);
      printBuffer("ControllerFWReply", (unsigned char *)(&radio_response), ret);

      /* Move to the next command if there is one */
      cur_controller_read->read_command_idx++;

      if (cur_controller_read->read_command_idx < (sizeof (riftS_fw_commands)/sizeof(riftS_fw_commands[0]))) {
          read_another = true;
      }
      else {
        /* All finished with this controller - bail */
        cur_controller_read->finished_fw_read = true;
        cur_controller_read = NULL;
      }
    } while (read_another);
}

static void
handle_hmd_report (const unsigned char *buf, int size)
{
  hmd_report_t report;

  if (!parse_hmd_report (&report, buf, size)) {
    printBuffer("Invalid HMD Report", buf, size);
  }

  if (!(dump_hmd || dump_all))
    return;

  if (!dump_parsed) {
    printBuffer("HMD", buf, size);
    return;
  }

  dump_hmd_report (&report, dump_singleline ? '\r' : '\n');
}

static void
handle_controller_report (const unsigned char *buf, int size)
{
  controller_report_t report;

  if (!parse_controller_report (&report, buf, size)) {
    printBuffer("Invalid Controller Report", buf, size);
  }

  if (read_controller_fw) {
    if (report.device_id != 0x00) {
      int i;
      controller_fw_state_t *ctrl = NULL;

        for (i = 0; i < num_controllers; i++) {
          if (controllers[i].device_id == report.device_id) {
            ctrl = controllers + i;
            break;
          }
        }

      if (ctrl == NULL) {
        if (num_controllers == MAX_CONTROLLERS) {
          fprintf (stderr, "Too many controllers. Can't add %08lx\n", report.device_id);
          return;
        }

        /* Add a new controller to the tracker */
        ctrl = controllers + num_controllers;
        num_controllers++;

        memset (ctrl, 0, sizeof (controller_fw_state_t));
        ctrl->device_id = report.device_id;
        printf ("Found new controller 0x%08lx\n", report.device_id);
      }
    }
  }

  if (dump_controllers || dump_all) {
    if (dump_parsed) {
      dump_controller_report (&report, dump_singleline ? '\r' : '\n');
    }
    else {
      printBuffer("Controller", buf, size);
      return;
    }
  }
}

static void
update_hmd_device (hid_device *hid)
{
  unsigned char buf[FEATURE_BUFFER_SIZE];

  // Read all the messages from the device.
  while(true){
    int size = hid_read(hid, buf, FEATURE_BUFFER_SIZE);
    if(size < 0){
      fprintf (stderr, "error reading from device");
      shutdown_and_exit = true;
      break;
    } else if(size == 0) {
      break; // No more messages, return.
    }

    if (buf[0] == 0x65)
      handle_hmd_report (buf, size);
    else if (buf[0] == 0x67)
      handle_controller_report (buf, size);
    else if (buf[0] == 0x66) {
      // System state packet. Enable the screen if the prox sensor is
      // triggered
      bool prox_sensor = (buf[1] == 0) ? false : true;
      if (prox_sensor != display_on) {
        set_screen_state (hid, prox_sensor);
        display_on = prox_sensor;
      }
    }
    else
     printBuffer("Unknown report!", buf, size);
  }
}

static uint64_t ohmd_monotonic_get()
{
  const uint64_t NUM_1_000_000_000 = 1000000000;
  static uint64_t monotonic_ticks_per_sec = 0;
  struct timespec now;

  if (monotonic_ticks_per_sec == 0) {
    struct timespec ts;
    if (clock_getres(CLOCK_MONOTONIC, &ts) !=  0) {
      monotonic_ticks_per_sec = NUM_1_000_000_000;
    }
    else {
      monotonic_ticks_per_sec =
            ts.tv_nsec >= 1000 ?
            NUM_1_000_000_000 :
            NUM_1_000_000_000 / ts.tv_nsec;
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &now);

  uint64_t ticks = now.tv_sec * NUM_1_000_000_000 + now.tv_nsec;

  if (monotonic_ticks_per_sec != NUM_1_000_000_000) {
    ticks = ticks / monotonic_ticks_per_sec * NUM_1_000_000_000 +
            ticks % monotonic_ticks_per_sec * NUM_1_000_000_000 / monotonic_ticks_per_sec;
  }

  return ticks;
}

int rift_s_read_imu_config (hid_device *hid, rift_s_imu_config_t *imu_config)
{
	int res = get_report(hid, 0x9, (unsigned char *)(imu_config), sizeof(rift_s_imu_config_t));
	if (res < 21)
		return -1;

	return 0;
}

static int sleep_us (uint64_t usec)
{
  struct timespec ts;
  int res;

  ts.tv_sec = usec / 1000000;
  ts.tv_nsec = (usec % 1000000) * 1000;

  do {
      res = nanosleep(&ts, &ts);
  } while (res && errno == EINTR);

  return res;
}

struct DeviceInfo {
  char cmd;
  uint16_t v_resolution;
  uint16_t h_resolution;
  uint16_t unk0;
  char refreshRate;
  int32_t unk1;
  int32_t unk2;
  int32_t unk3;
  uint16_t unk4;
} __attribute__((aligned(1), packed));

static void
print_usage (const char *argv0)
{
  printf ("Usage %s [-f] [-c] [-h]\n", argv0);
  printf ("  -f print firmware dumps\n");
  printf ("  -c print controller reports only\n");
  printf ("  -h print HMD reports only\n");
  printf ("  -s print HMD or Controller report on a single line using \\r\n");
  printf ("  -p Parse HMD or Controller reports\n");
  printf ("  -r Send Controller FW read commands\n");
}

int main(int argc, char **argv) {
  struct DeviceInfo devInfo;
  int a;

  struct sigaction sigint_action;
  sigint_action.sa_handler = sigint_handler;
  sigemptyset (&sigint_action.sa_mask);
  sigint_action.sa_flags = 0;

  sigaction (SIGINT, &sigint_action, NULL);

  for (a = 1; a < argc; a++) {
    if (strcmp (argv[a], "-c") == 0) {
      dump_all = false;
      dump_controllers = true;
    } else if (strcmp (argv[a], "-h") == 0) {
      dump_all = false;
      dump_hmd = true;
    } else if (strcmp (argv[a], "-f") == 0) {
      dump_all = false;
      dump_fw = true;
    } else if (strcmp (argv[a], "-p") == 0) {
      dump_parsed = true;
    } else if (strcmp (argv[a], "-s") == 0) {
      dump_singleline = false;
    } else if (strcmp (argv[a], "-r") == 0) {
      read_controller_fw = true;
    } else {
      print_usage (argv[0]);
      exit (0);
    }
  }

  struct hid_device_info* dev = hid_enumerate(0x2833, 0x0051);
  if (dev == NULL) {
    printf("No Rift S found\n");
    return 1;
  }

  struct hid_device_info *hmd_dev = NULL;
  struct hid_device_info *controller_dev = NULL;
  struct hid_device_info *state_dev = NULL;

  struct hid_device_info *d = dev;
  while (d != NULL) {
    //printf("%d\n", d->interface_number);
    if (d->interface_number == 0x06) {
      hmd_dev = d;
    }
    else if (d->interface_number == 0x07) {
      state_dev = d;
    }
    else if (d->interface_number == 0x08) {
      controller_dev = d;
    }
    d = d->next;
  }

  if (hmd_dev == NULL || state_dev == NULL || controller_dev == NULL) {
    printf("No Rift S found\n");
    return 1;
  }

  printf("FOUND Rift S\n");

  hid_device *hid_hmd = hid_open_path(hmd_dev->path);
  if (hid_hmd == NULL) {
    printf("FAIL to open HID device at %s: %ls\n", hmd_dev->path, hid_error(hid_hmd));
    return 1;
  }
  if (hid_set_nonblocking(hid_hmd, 1) == -1){
    fprintf (stderr, "failed to set non-blocking on HMD device");
    goto cleanup;
  }

  hid_device *hid_controller = hid_open_path(controller_dev->path);
  if (hid_controller == NULL) {
    printf("FAIL to open HID device at %s: %ls\n", controller_dev->path, hid_error(hid_controller));
    return 1;
  }
  if (hid_set_nonblocking(hid_controller, 1) == -1){
    fprintf (stderr, "failed to set non-blocking on Controller tracking device");
    goto cleanup;
  }

  hid_device *hid_state = hid_open_path(state_dev->path);
  if (hid_state == NULL) {
    printf("FAIL to open HID device at %s: %ls\n", state_dev->path, hid_error(hid_state));
    return 1;
  }
  if (hid_set_nonblocking(hid_state, 1) == -1){
    fprintf (stderr, "failed to set non-blocking on System State device");
    goto cleanup;
  }


  unsigned char buff[65];

  int b = get_report(hid_hmd, 0x06, buff, sizeof(devInfo));
  if (b < sizeof(devInfo)) {
    printf("Failed to read %d of device info\n", (int) sizeof(devInfo));
    exit(1);
  }
  memcpy(&devInfo, buff, sizeof (devInfo));
  printBuffer("display info", buff, b);

  clear_buff(buff, 65);
  printf("Horiz: %u\nVert: %u\nHz: %u\n", devInfo.h_resolution, devInfo.v_resolution, devInfo.refreshRate);
  printf("Unk0: %u\nUnk1: %d\nUnk2: %d\nUnk3: %d\nUnk4: %u\n", devInfo.unk0, devInfo.unk1, devInfo.unk2, devInfo.unk3, devInfo.unk4);

  b = get_report(hid_hmd, 0x01, buff, 43);
  if (b < 0) {
    printf("Failed to read report 1\n");
    exit(1);
  }
  printBuffer("report 1", buff, b);

	rift_s_imu_config_t imu_config;
  if (rift_s_read_imu_config (hid_hmd, &imu_config) >= 0) {
		printf ("IMU config %u Hz. Gyro scale %f Accel scale %f Temperature scale %f offset %f\n",
			imu_config.imu_hz, imu_config.gyro_scale, imu_config.accel_scale,
			imu_config.temperature_scale, imu_config.temperature_offset);
  }
	else {
		printf ("Failed to read IMU config block\n");
	}

  buff[0] = 0x07;
  buff[1] = 0xa3;
  buff[2] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 3); // Unknown

  if (dump_fw || dump_all) {
    /* Dump firmware blocks. Higher blocks don't have anything, some lower blocks crash the headset */
    // dump_fw_block(hid_hmd, 1); // Enable this to dump a bunch of interesting firmware blob
    dump_fw_block(hid_hmd, 0xB);
    dump_fw_block(hid_hmd, 0xD);
    dump_fw_block(hid_hmd, 0xE);
    dump_fw_block(hid_hmd, 0xF);
    dump_fw_block(hid_hmd, 0x10);
    dump_fw_block(hid_hmd, 0x12);
  }

  buff[0] = 0x14;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Not sure what this is doing, everything seems to work anyway without it

  buff[0] = 0x0A;
  buff[1] = 0x02;
  hid_send_feature_report(hid_hmd, buff, 2); // Turn on radio to controllers

  buff[0] = 0x02;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Enables prox sensor + HMD IMU etc

  /* Send camera report with enable=true enables the streaming. The
   * 2nd byte seems something to do with sync, but doesn't always work,
   * not sure why yet. */
  send_camera_report (hid_hmd, 1, 0);

  /* Loop until exit polling devices and sending keep-alive */
  uint64_t last_keepalive = 0;
  while(!shutdown_and_exit)
  {
    uint64_t now;
    sleep_us (1000);

    now = ohmd_monotonic_get();
    if (now - last_keepalive >= KEEPALIVE_INTERVAL_MS * 1000000) {
      send_keepalive (hid_hmd);
      last_keepalive = now;
    }

    update_hmd_device (hid_hmd);

    /* State report is 5 bytes. Byte 0 = 00 or 01 based on prox sensor */
    update_hmd_device (hid_state);

    update_hmd_device (hid_controller);

    /* Schedule or check on controller fw reads */
    update_controller_fw_read(hid_hmd);
  }

cleanup:
  if (hid_hmd) {
    /* Disable camera stream */
    send_camera_report (hid_hmd, 0, 0);

    buff[0] = 0x02;
    buff[1] = 0x00;
    hid_send_feature_report(hid_hmd, buff, 2); // Disable HMD + prox sensor

    set_screen_state (hid_hmd, false); // Disable LCD

    buff[0] = 0x0A;
    buff[1] = 0x00;
    hid_send_feature_report(hid_hmd, buff, 2); // Disable radio

    buff[0] = 0x14;
    buff[1] = 0x00;
    hid_send_feature_report(hid_hmd, buff, 2); // Disable something

    hid_close(hid_hmd);
  }

  if (hid_controller)
    hid_close(hid_controller);
  hid_free_enumeration(dev);
}
