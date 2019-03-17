# Ferramenta de análise de pacotes

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
