import datetime
from scapy.all import *

def capture(dado):
	with open("Output.txt", "a") as text_file:
	    import datetime
	    text_file.write(str(datetime.datetime.now())+" "+str(dado.sprintf("{IP:%IP.src% %IP.dst% %IP.len% %IP.proto%\n}")))

sniff(iface="eth0", prn=capture, timeout=10)
