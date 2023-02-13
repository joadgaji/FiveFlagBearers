#!/usr/bin/env python3
import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sniff, sendp
import json

global broadcast
global interface
global database

def main():
    print("Python version=" + sys.version)
    print("Python executable=" + sys.executable)
    print("Scapy version=" + scapy._version())
    data = parse_arguments();
    loadStaticTable();
    print(data);

    global broadcast
    global interface
    global database

    values = "";
    for i in database:
        print(i);
        if i.endswith("255"):
            broadcast = i;
        else:
            values = values + " dst host " + i + " or";

    print(values[:-3]);

    interface = data.interface

    sniff(iface=interface, filter=values[:-3],
          prn=handle_packet)


def loadStaticTable():
    global database;

    file = open("database2.txt", "r");
    data = file.readlines();
    print(data)
    file.close()
    database = json.loads(data[0]);


def handle_packet(packet):
    """
    Method that handles the packets.

    For the moment we can handle ARP, ICMP, UDP and TCP
    """
    if ARP in packet:
        global database
        global broadcast

        print(broadcast)
        if packet["ARP"].pdst in database and packet["ARP"].op == 1:
            print("Posible arp " + packet["ARP"].pdst);
            #print("IP dest:" + packet["ARP"].pdst )
            #print("HW dest:" + database[packet["ARP"].pdst])
            #print("IP ori:" + packet["ARP"].psrc)
            #print("HW ori:" + packet["ARP"].hwsrc)
            packet_send = ARP(op=2, pdst=broadcast,
                              hwdst="ff:ff:ff:ff:ff:ff",
                              psrc=packet["ARP"].pdst,
                              hwsrc=database[packet["ARP"].pdst])
            ether = Ether(dst="ff:ff:ff:ff:ff:ff",
                          src=database[packet["ARP"].pdst]) / packet_send
            sendp(ether, iface=interface)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog='Reflector')

    parser.add_argument('--interface', required=True)

    args = parser.parse_args();
    return args;


if __name__ == '__main__':
    main()
