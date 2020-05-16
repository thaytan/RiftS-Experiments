
typedef struct {
  uint8_t cmd;
  uint8_t cmd_bytes[10];
} riftS_fw_command_t;

riftS_fw_command_t riftS_fw_commands[] = {
  { 0x12, { 0x32, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x31, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x28, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x24, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
  { 0x13, { 0x06, 0x01, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x03, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x02, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00 }, },
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
  { 0x12, { 0x2b, 0x20, 0xe8, 0x03, 0x64, 0x09, 0x00, 0x00, 0x02, 0x00 }, },

  { 0x12, { 0x99, 0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
  { 0x12, { 0x99, 0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x13, { 0x06, 0x01, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x13, { 0x97, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x13, { 0x98, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }, },

  { 0x13, { 0x97, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, },
};