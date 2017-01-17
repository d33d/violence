#!/usr/bin/env python
import argparse
import os.path
from scapy.all import *

VER  = "v0.1"
pkts = []
srchost = None
dsthost = ""
dstport = ""

interface = None
dstsocket = None
dststream = None

def pkt_collect(p):
    print p.summary()
    pkts.append(p)

def start_sniff(p_num, pfile, net_filter):
    sniff(filter=net_filter,iface=interface,prn=pkt_collect,store=0,count=p_num)
    wrpcap(pfile, pkts)

def pkt_fuzz(p):
    if TCP in p and p[TCP].dport == dstport and p[TCP].payload:
        
        if srchost:
            p[IP].src = srchost
        
        p[IP].dst  = dsthost
        if p[TCP].payload:
            print "[*] Fuzzing Payload...\n"
        
        print p.summary()
        
        response = dststream.send(fuzz(p.getlayer(Raw)))
        print "[*] Length: %s" %(response)

def start_fuzz(pfile):
    sniff(offline=pfile, prn=pkt_fuzz)
    
def check_mode(string):
    if string != "sniff" and string != "fuzz":
        msg = "%r is not a valid Violence execution mode" % string
        raise argparse.ArgumentTypeError(msg)
    else:
        return string

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Violence - ' + VER)
    p.add_argument('-m', '--mode', default='sniff', type=check_mode, help='collect some useful network data')
    p.add_argument('-c', '--count', default=10, help='how many packets to collect')
    p.add_argument('-o', '--pcapfile', default='violence.pcap', help='pcap file')
    p.add_argument('-f', '--filter', default="tcp port 80", help='packet filter in bpf syntax')
    p.add_argument('-v', '--host', default=None, help='dest host of fuzzing')
    p.add_argument('-p', '--port', default=None, help='dest port of fuzzing')
    p.add_argument('-i', '--iface', default="eno2", help='network interface') 
    args = p.parse_args()
    
    interface = args.iface
    
    if args.mode == 'sniff':
        
        print "\n[*] Start sniffing...\n"
        start_sniff(args.count, args.pcapfile, args.filter)
    if args.mode == 'fuzz':
        if os.path.isfile(args.pcapfile):
            dsthost   = args.host
            dstport   = int(args.port)
            dstsocket = socket.socket()
            dstsocket.connect((dsthost, dstport))
            
            print "[*] Connecting to %s on port %s\n" %(dsthost, dstport)
            dststream = StreamSocket(dstsocket)
            
            #print "[*] Test connection with random data...\n"
            #testpkt = IP(dst=dsthost)/TCP(dport=dstport)/fuzz(Raw())
            #resp = dststream.send(testpkt)
            #print resp
            
            print "\n[*] Start fuzzing. Feeding fuzzer with %s\n" %(args.pcapfile)
            start_fuzz(args.pcapfile)
        else:
            print "\n[*] Unable to find %s\n" %(args.outfile)

