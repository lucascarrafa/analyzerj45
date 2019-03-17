from scapy.all import *

def capture(dado):
	with open("Output.txt", "a") as text_file:
	    text_file.write(str(dado.sprintf("{IP:%IP.src% %IP.dst% %IP.len%\n}")))
	    #text_file.write(str(dado.sniffed_on+": "+dado.summary()+"\n"))

sniff(iface="eth0", prn=capture, count=100)
