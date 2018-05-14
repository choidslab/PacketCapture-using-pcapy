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

# Convert a MAC addr to a readable/printable string.
def mac_addr(address):
    return ':'.join('%02x' % ord(b) for b in address)

# Print out an IP addr given a string.
def ip_addr(address):
    return socket.inet_ntop(socket.AF_INET, address)

# Callback Function for packet handling.
def packet_handler(hdr, pkt):

    # Get src IP, dst IP from pkt.
    eth = dpkt.ethernet.Ethernet(pkt)
    srcMAC = mac_addr(eth.src)
    dstMAC = mac_addr(eth.dst)

    # Get src IP from pkt.
    ip = eth.data
    srcIP = ip_addr(ip.src)

    # Get packet capture time.
    accesstime = datetime.today().strftime("%Y.%m.%d %H:%M:%S")
    print("Access from: %s\t|\t%s\t|\t%s" % (srcIP, srcMAC, accesstime))

    # Record a packet to .pcap file.
    dumper.dump(hdr, pkt)

if __name__ == "__main__":

    # NIC(Network Interface Card) info, "ifconfig -a"
    dev = "eth0"
    # Capture packets using open_live(NIC, Capture bytes size, Promiscuous Mode, Read timeout)
    pkt = open_live(dev, 65535, True, 0)

    try:
        while True:
            # Set .pcap file's filename using datetime.
            filename = datetime.today().strftime("%Y%m%d%H%M%S")
            # Set capture filter(BPF filter), In this case, capture only tcp packets.
            pkt.setfilter("tcp")
            # Create .pcap file.
            dumper = pkt.dump_open("./%s.pcap" % filename)

            # Call packet_handler() function, Save up to 10,000 packets.
            pkt.loop(10000, packet_handler)

    # You can stop the program using 'Ctrl + C'
    except KeyboardInterrupt:
        print("Keyboard Interrupt!")
        pass