import datetime
import sys
import os
import commands

resp_terminal = commands.getoutput("pip list")
if resp_terminal.find("scapy") == -1:
	os.system("sudo pip install scapy")
	print("\n\n##########| Ajustes realizados com sucesso |##########\n")
else:
	 print("Ambiente esta pronto\n")


from scapy.all import *


def capture(dado):
	with open(str(sys.argv[3]), "a") as text_file:
		import datetime
	        text_file.write(str(datetime.datetime.now())+" "+str(dado.sprintf("{IP:%IP.src% %IP.dst% %IP.len% %IP.proto%}"))+"\n")

print("Capturando os pacotes...")
sniff(iface=str(sys.argv[1]), prn=capture, store=1, timeout=int(sys.argv[2]))
