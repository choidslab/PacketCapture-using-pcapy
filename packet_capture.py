# -*- coding: utf-8 -*-
""" This is packet capture program using pcapy module.
    created date: 2016-05-19 
    last modified date: 2018-05-13
    made by DS.Choi
"""
import dpkt
import socket
from datetime import datetime
from pcapy import *

# Convert a MAC addr to a readable/printable string
def mac_addr(address):
    return ':'.join('%02x' % ord(b) for b in address)

# Print out an IP addr given a string
def ip_addr(address):
    return socket.inet_ntop(socket.AF_INET, address)

def packet_handler(hdr, pkt):

    eth = dpkt.ethernet.Ethernet(pkt)
    srcMAC = mac_addr(eth.src)
    dstMAC = mac_addr(eth.dst)

    ip = eth.data
    srcIP = ip_addr(ip.src)

    accesstime = datetime.today().strftime("%Y.%m.%d %H:%M:%S")
    print("Access from: %s\t|\t%s\t|\t%s" % (srcIP, srcMAC, accesstime))

    dumper.dump(hdr, pkt)

if __name__ == "__main__":

    dev = "eth0"
    # Capture the packets
    pkt = open_live(dev, 65535, True, 0)

    try:
        while True:
            # Dumpfile name Setting -> Create Time
            filename = datetime.today().strftime("%Y%m%d%H%M%S")
            # Capture Filter - BPF Filter Syntax
            pkt.setfilter("tcp")
            # pkt.setfilter("((tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354))")
            # packet dump file (file open)
            dumper = pkt.dump_open("./%s.pcap" % filename)

            # packet_handler callback function
            pkt.loop(10000, packet_handler)

    except KeyboardInterrupt:
        print("Keyboard Interrupt!")
        pass