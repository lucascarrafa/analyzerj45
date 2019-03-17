from scapy.all import *

#pkt = sniff(iface="eth0", prn=capture, count=5)
#pkt = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"))

def capture(dado):
	with open("Output.txt", "a") as text_file:
	    text_file.write(str(dado.sprintf("{IP:%IP.src% -> %IP.dst%\n}")))
	    #text_file.write(str(dado.sniffed_on+": "+dado.summary()+"\n"))


sniff(iface="eth0", prn=capture, count=100)
