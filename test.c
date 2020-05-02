#include <stdio.h>
#include <hidapi/hidapi.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define FEATURE_BUFFER_SIZE 64

bool done = false;

static void
sigint_handler (int signum)
{
    done = true;
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

static void
send_keepalive (hid_device *hid)
{
  /* HID report 147 (0x93) 0xbb8 = 3000ms timeout, sent every 1000ms */
  unsigned char buf[6] = { 0x93, 0x01, 0xb8, 0x0b, 0x00, 0x00 };
  hid_send_feature_report(hid, buf, 6);
}

static void
update_hmd_device (const char *label, hid_device *hid)
{
  unsigned char buf[FEATURE_BUFFER_SIZE];

  // Read all the messages from the device.
  while(true){
    int size = hid_read(hid, buf, FEATURE_BUFFER_SIZE);
    if(size < 0){
      fprintf (stderr, "error reading from device");
      done = true;
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

int sleep_us (uint64_t usec)
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
  }
  memcpy(&devInfo, buff, sizeof (devInfo));
  printBuffer("display info", buff, b);

  clear_buff(buff, 65);
  printf("Horiz: %u\nVert: %u\nHz: %u\n", devInfo.h_resolution, devInfo.v_resolution, devInfo.refreshRate);
  printf("Unk0: %u\nUnk1: %d\nUnk2: %d\nUnk3: %d\nUnk4: %u\n", devInfo.unk0, devInfo.unk1, devInfo.unk2, devInfo.unk3, devInfo.unk4);

  buff[0] = 0x07;
  buff[1] = 0xa3;
  buff[2] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 3); // Unknown

  buff[0] = 0x02;
  buff[1] = 0x00;
  hid_send_feature_report(hid_hmd, buff, 2); // Disables HMD

  clear_buff(buff, 65);
  buff[0] = 0x14;
  buff[1] = 0x01;

  hid_send_feature_report(hid_hmd, buff, 2); // Enables Camera Device

  clear_buff(buff, 65);
  printf("Sending 0x0A 0x02\n");

  buff[0] = 0x0A;
  buff[1] = 0x02;

  hid_send_feature_report(hid_hmd, buff, 2); // Turn on Wireless

  clear_buff(buff, 65);

  buff[0] = 0x02;
  buff[1] = 0x01;
  hid_send_feature_report(hid_hmd, buff, 2); // Enables HMD

  /* Loop until exit polling devices and sending keep-alive */
  uint64_t last_keepalive = ohmd_monotonic_get();
  while(!done)
  {
    uint64_t now;
    sleep_us (1000);

    now = ohmd_monotonic_get();
    if (now - last_keepalive >= 1000000000) {
      send_keepalive (hid_hmd);
      last_keepalive = now;
    }

    update_hmd_device ("HMD       ", hid_hmd);
    update_hmd_device ("State     ", hid_state);
    update_hmd_device ("Controller", hid_controller);
  }

cleanup:
  if (hid_hmd)
    hid_close(hid_hmd);
  if (hid_controller)
    hid_close(hid_controller);
  hid_free_enumeration(dev);
}
