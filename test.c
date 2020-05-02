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

#define FEATURE_BUFFER_SIZE 64

#define KEEPALIVE_INTERVAL_MS 1000
#define CAMERA_REPORT_INTERVAL_MS 1000

bool shutdown_and_exit = false;

static int sleep_us (uint64_t usec);

static void
sigint_handler (int signum)
{
    shutdown_and_exit = true;
}

static void printBuffer(const char *label, unsigned char *buf, int length) {
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

#if 0
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

static void
update_hmd_device (const char *label, hid_device *hid)
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

    printBuffer(label, buf, size);
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

int main() {
  struct DeviceInfo devInfo;

  struct sigaction sigint_action;
  sigint_action.sa_handler = sigint_handler;
  sigemptyset (&sigint_action.sa_mask);
  sigint_action.sa_flags = 0;

  sigaction (SIGINT, &sigint_action, NULL);

  struct hid_device_info* dev = hid_enumerate(0x2833, 0x0051);
  if (dev == NULL) {
    printf("Not found\n");
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

  buff[0] = 0x07;
  buff[1] = 0xa3;
  buff[2] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 3); // Unknown

  /* Dump firmware blocks. Higher blocks don't have anything, some lower blocks crash the headset */
  dump_fw_block(hid_hmd, 1);
  for (int blk = 9; blk < 0x13; blk++)
    dump_fw_block(hid_hmd, blk);

  buff[0] = 0x14;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Not sure what this is doing, everything seems to work anyway without it

  buff[0] = 0x0A;
  buff[1] = 0x02;
  hid_send_feature_report(hid_hmd, buff, 2); // Turn on radio to controllers

  buff[0] = 0x02;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Enables prox sensor + HMD IMU etc

  buff[0] = 0x08;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Enables LCD screen

  /* Send camera report with enable=true enables the streaming. The
   * 2nd byte seems something to do with sync, but doesn't always work,
   * not sure why yet. */
  send_camera_report (hid_hmd, 1, 0);

  /* Loop until exit polling devices and sending keep-alive */
  uint64_t last_keepalive = 0;
  uint64_t last_report19 = 0;
  while(!shutdown_and_exit)
  {
    uint64_t now;
    sleep_us (1000);

    now = ohmd_monotonic_get();
    if (now - last_keepalive >= KEEPALIVE_INTERVAL_MS * 1000000) {
      send_keepalive (hid_hmd);
      last_keepalive = now;
    }

    update_hmd_device ("HMD       ", hid_hmd);

    /* State report is 5 bytes. Byte 0 = 00 or 01 based on prox sensor */
    update_hmd_device ("State     ", hid_state);

    update_hmd_device ("Controller", hid_controller);
  }

cleanup:
  if (hid_hmd) {
    /* Disable camera stream */
    send_camera_report (hid_hmd, 0, 0);

    buff[0] = 0x02;
    buff[1] = 0x00;
    hid_send_feature_report(hid_hmd, buff, 2); // Disable HMD + prox sensor

    buff[0] = 0x08;
    buff[1] = 0x00;
    hid_send_feature_report(hid_hmd, buff, 2); // Disable LCD

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
