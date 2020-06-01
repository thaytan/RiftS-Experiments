
typedef struct {
  uint8_t cmd;
  uint8_t cmd_bytes[10];
} riftS_fw_command_t;

riftS_fw_command_t riftS_fw_commands[] = {
  { 0x12, { 0x32, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x10   00 7d a0 0f f4 01 f4 01 00 00 80 3a ff ff f9 3d
     *   0x7d00 = 32000
     *   0x0fa0 = 4000
     *   0x01f4 = 500
     *   0x01f4 = 500
     *   0x3a800000 = 0.9765625e-03
     *   0x3df9ffff = 0.1220703
     *
     *   Same on both controllers
     */

  { 0x12, { 0x31, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x10   49 43 4d 32 30 36 30 31 00 00 80 3a ff ff f9 3d
     *  = "ICM20601\0" is an Invensense IMU.
     *  The remainder is left from the previous packet */

  { 0x12, { 0x28, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x08   35 82 00 00 13 00 00 00
     * 0x8235 = 33333
     *   0x0000 (=0)  0x0013 (=19) 0x0000
     * other controller has 0x08     40 9c 00 00 13 00 00 00
     * 0x9c40 = 40000
     *   0x0000 (=0)  0x0013 (=19) 0x0000 */

  { 0x12, { 0x24, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x1c                           01 0e 02 00 64 36 39 65 | .q..........d69e
                            38 38 30 65 39 35 37 38                         | 880e9578
       = 0x1 0xe (status 1 len 0xe?) 02 00
         fw version d69e880e9578 (same on the other controller) */

  { 0x12, { 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x01   00 */

  { 0x13, { 0x06, 0x01, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup B 1st */
    /* Response 0u32 0x00 */

  { 0x12, { 0x03, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x10                           31 50 41 4c 43 4c 43 54 | .w......1PALCLCT
                            31 43 39 35 31 32 00 00                         | 1C9512..
       Serial # - QR codes inside the controller */

  { 0x12, { 0x02, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
    /* Response 0u32 0x10                           31 50 41 4c 43 47 42 56 | .y......1PALCGBV
                            39 53 39 34 38 35 00 00                         | 9S9485..
       Serial # - QR codes inside the controller */

   /* Configuration JSON block reading */
   /*       cmd  = 0x2b  read length = 0x20  unk2 = 0x3e8 (=1000) common to most req cmd types
    *       offset = 0u32   len = 0x20 */
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
    /* Response 0u32 0x20                           01 00 62 09 7b 22 67 79 | .{..... ..b.{"gy
                            72 6f 5f 6d 22 3a 5b 2d 30 2e 30 31 34 33 35 36 | ro_m":[-0.014356
                            38 38 36 36 2c 2d 30 2e                         | 8866,-0.
        = len 0x20, 0001 (file type, or sequence number?), 0x0962 = file length */

  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00 }, }, /* offset 0x4, len 0x20 */
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x01, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x02, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x03, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x04, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x05, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x06, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x07, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x84, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xa4, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xc4, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0xe4, 0x08, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x09, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x24, 0x09, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x44, 0x09, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x09, 0x00, 0x00, 0x02, 0x00 }, }, /* offset 0x964 + 0x02 = end @ 0x966 */

  { 0x12, { 0x99, 0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup A 1st */
      /* Response 0u32  11 01 64 ff d0 07  = 0x0111 0xff64 0x7d0 = 273, -155, 2000 ? */
  { 0x12, { 0x99, 0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup A 2nd */
      /* Response 0u32  11 01 64 ff d0 07  */

  { 0x13, { 0x06, 0x01, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup B 2nd */
      /* Response 0u32  0x00 */

  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup D 1st */
      /* Response 0u32  0x00 */
  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup D 2nd */
      /* Response 0u32  0x00 */

  { 0x13, { 0x97, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup C 1st */
      /* Response 0u32  0x00 */

  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup D 3rd */
      /* Response 0u32  0x00 */

  { 0x13, { 0x97, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, }, /* Dup C 2nd */
      /* Response 0u32  0x00 */
};
