# Ferramenta de análise de pacotes
![Imagem](/imagem/logo.PNG)
Versão 0.1

## Requisitos

Sistema Operacional Linux

Python 2.7 adiante

## Executando o Analyzerj45

Para capturar os pacotes basta executar o seguinte comando:

```
sudo python analyzerj45.py [interface] [tempo] [nome do arquivo]
```
interface: campo para especificar a interface de rede

tempo: passa o tempo de coleta de dados em segundos

nome do arquivo: nome do arquivo que serão salvos os pacotes

**Exemplo**
```
sudo python analyzerj45.py eth0 10 computador01
```

## Executando a análise de dados

Antes de utilizar esse recurso, certifique-se que o _pandas_ está devidamente instalado no Sistema

Para análise dos dados basta executar o seguinte comando:

```
python proc_dados.py [nome do arquivo]
```

**Exemplo**
```
python proc_dados.py computador01
```

## Parâmetros do sniff 
```
sniff(count=0, store=1, offline=None, prn=None, lfilter=None, L2socket=None, timeout=None, *arg, **karg)
    Sniff packets
    sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
    Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
      count: number of packets to capture. 0 means infinity
      store: wether to store sniffed packets or discard them
        prn: function to apply to each packet. If something is returned,
             it is displayed. Ex:
             ex: prn = lambda x: x.summary()
    lfilter: python function applied to each packet to determine
             if further action may be done
             ex: lfilter = lambda x: x.haslayer(Padding)
    offline: pcap file to read packets from, instead of sniffing them
    timeout: stop sniffing after a given time (default: None)
    L2socket: use the provided L2socket
```
