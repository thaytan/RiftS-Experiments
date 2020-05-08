/*
 * Copyright 2020 Jan Schmidt <jan#centricular.com>
 * SPDX-License-Identifier: BSL-1.0
 *
 * Reads the hexdump HMD and Controller report lines from
 * a log file generated by the dump-rift-s tool and prints
 * the parsed result
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include "packets.h"

typedef enum {
  STATE_NONE,
  STATE_HMD_BLOCK,
  STATE_CONTROLLER_BLOCK
} read_state_t;

typedef struct {
  uint8_t data[64];
  int size;
} packet_buf_t;

static bool is_hexchar (char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int hexval (char c) {
  if (c >= '0' && c <= '9')
    return c -'0';
  if (c >= 'A' && c <= 'F')
    return c -'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c -'a' + 10;
  return -1;
}

/* Read a row of hexdump formatted hex bytes and append
 * them to the packet, or fail if things don't match the
 * format we expect */
static bool
append_to_packet (char *readbuf, packet_buf_t *packet) {
  bool in_hexblock = false;

  while (readbuf[0] == ' ' || readbuf[0] == ':')
    readbuf++;

  while (readbuf[0] != '\0') {
    if (is_hexchar (readbuf[0]) && is_hexchar (readbuf[1])) {
      uint8_t val = hexval(readbuf[0]) << 4 | hexval(readbuf[1]);
      if (packet->size >= sizeof (packet->data))
        return false; // No room for this byte
      packet->data[packet->size++] = val;
      readbuf++;
      in_hexblock = true;
    }
    else if (in_hexblock && readbuf[0] != ' ')
      break; // Reached the end of the hex area
    readbuf++;
  }

  return true;
}

/* Process the bytes of a collected packet */
static bool
handle_packet (packet_buf_t *packet) {
  if (packet->size < 1)
    return false;

  switch (packet->data[0]) {
    case 0x65: {
      hmd_report_t report;
      if (!parse_hmd_report (&report, packet->data, packet->size)) {
        printf ("Invalid HMD report\n");
        return false;
      }
      printf ("HMD ");
      dump_hmd_report (&report, '\n');
      printf ("  ");
      hexdump_bytes(packet->data, packet->size);
      printf ("\n");
      break;
    }
    case 0x67: {
      controller_report_t report;
      if (!parse_controller_report (&report, packet->data, packet->size)) {
        printf ("Invalid Controller report\n");
        return false;
      }
      printf ("Controller ");
      dump_controller_report (&report, '\n');
#if 0
      printf ("  ");
      hexdump_bytes(packet->data, packet->size);
      printf ("\n");
#endif
      break;
    }
    default:
      return false;
  }
  return true;
}

int
main (int argc, char **argv)
{
  char readbuf[1024];
  const char hmd_prefix[] = "HMD";
  const char controller_prefix[] = "Controller";
  read_state_t state = STATE_NONE;
  int line = 0;
  packet_buf_t packet = { 0, };

  while (fgets (readbuf, sizeof(readbuf), stdin))
  {
    line++;

    if (strncmp (readbuf, hmd_prefix, sizeof (hmd_prefix)-1) == 0) {
      if (packet.size > 0) {
        if (!handle_packet (&packet)) {
          printf ("Error in packet data preceding line %d: %s\n", line, readbuf);
          exit(1);
        }
        packet.size = 0;
      }

      state = STATE_HMD_BLOCK;
      if (!append_to_packet (readbuf + strlen(hmd_prefix), &packet)) {
        printf ("Error reading line %d: %s\n", line, readbuf);
        exit(1);
      }
    }
    else if (strncmp (readbuf, controller_prefix, sizeof (controller_prefix)-1) == 0) {
      if (packet.size > 0) {
        if (!handle_packet (&packet)) {
          printf ("Error in packet data preceding line %d: %s\n", line, readbuf);
          exit(1);
        }
        packet.size = 0;
      }

      state = STATE_CONTROLLER_BLOCK;
      if (!append_to_packet (readbuf + strlen(controller_prefix), &packet)) {
        printf ("Error reading line %d: %s\n", line, readbuf);
        exit(1);
      }
    }
    else if (readbuf[0] == ' ') {
      /* Read a continuation line in an existing block */
      if (state == STATE_HMD_BLOCK || state == STATE_CONTROLLER_BLOCK) {
        if (!append_to_packet (readbuf, &packet)) {
          printf ("Error reading line %d: %s\n", line, readbuf);
          exit(1);
        }
      }
    }
  }
}

