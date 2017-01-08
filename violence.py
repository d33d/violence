import argparse
import os.path
from scapy.all import *

VER  = "v0.1"
pkts = []

def pkt_collect(p):
    print p.summary()
    pkts.append(p)

def start_sniff(p_num, pfile, net_filter):
    sniff(filter=net_filter,iface='eno2',prn=pkt_collect,store=0,count=p_num)
    wrpcap(pfile, pkts)

def pkt_fuzz(p):
    print p.summary()
    if TCP in p and (p[TCP].sport == 80 or p[TCP].dport == 80):
        print p.show()

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
    p.add_argument('-p', '--pcapfile', default='violence.pcap', help='pcap file')
    p.add_argument('-f', '--filter', default="tcp port 80", help='packet filter in bpf syntax')
    args = p.parse_args()

    if args.mode == 'sniff':
        print "\n[*] Start sniffing...\n"
        start_sniff(args.count, args.pcapfile, args.filter)
    if args.mode == 'fuzz':        
        if os.path.isfile(args.pcapfile):
            print "\n[*] Start fuzzing. Feeding fuzzer with %s\n" %(args.pcapfile)
            start_fuzz(args.pcapfile)
        else:
            print "\n[*] Unable to find %s\n" %(args.pcapfile)

