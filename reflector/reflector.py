#!/usr/bin/env python

import sys
import getopt
import scapy.all as scapy

interface = ''
victimip = ''
victimeth = ''
reflectorip = ''
reflectoreth = ''

def packet_callback(packet):
    atteth = packet[scapy.Ether].src

    if scapy.ARP in packet:
        if packet[scapy.ARP].op == 1:
            print("it's arp!!!!!")
            print(packet.show())
            attip = packet[scapy.ARP].psrc
            if packet[scapy.ARP].pdst == victimip:
                arpresponse = scapy.Ether(src = victimeth, dst = atteth)/scapy.ARP(op = 2, pdst = attip, hwdst = atteth, psrc = victimip, hwsrc = victimeth)
            else:
                arpresponse = scapy.Ether(src = reflectoreth, dst = atteth)/scapy.ARP(op = 2, pdst = attip, hwdst = atteth, psrc = reflectorip, hwsrc = reflectoreth)
            print(arpresponse.show())
            scapy.sendp(arpresponse)
    else:
        print(packet.show())
        attip = packet[scapy.IP].src
        packet[scapy.Ether].dst = atteth
        if packet[scapy.IP].dst == victimip:
            packet[scapy.Ether].src = reflectoreth
            packet[scapy.IP].src = reflectorip
        else:
            packet[scapy.Ether].src = victimeth
            packet[scapy.IP].src = victimip
        packet[scapy.IP].dst = attip
        del packet.chksum

        if scapy.TCP in packet or scapy.UDP in packet:
            print("tcp or udp attack!")
            del packet.getlayer(2).chksum 
            print(packet.show())
            scapy.sendp(packet)
        else:
            print("ip attack!")
            scapy.sendp(packet)

def main(argv):
    global interface, victimip, victimeth, reflectorip, reflectoreth
    try:
        opts, _ = getopt.getopt(argv, '', [
                                "interface=", "victim-ip=", "victim-ethernet=", "reflector-ip=", "reflector-ethernet="])

    except getopt.GetoptError:
        print("wrong parameters")
        print("./reflector --interface <ethernet> --victim-ip <victim-ip> --victim-ethernet <victim-ethernet> --reflector-ip <reflector-ip> --reflector-ethernet <reflector-ethernet>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "--interface":
            interface = arg
        elif opt == "--victim-ip":
            victimip = arg
        elif opt == "--victim-ethernet":
            victimeth = arg
        elif opt == "--reflector-ip":
            reflectorip = arg
        elif opt == "--reflector-ethernet":
            reflectoreth = arg

    # scapy.conf.iface = interface
    # scapy.conf.verb = 0

    try:
        # filterstring = "ip dst " + victimip + " or arp dst " + victimip
        filterstring = "ip dst " + victimip + " or " + reflectorip + " or arp dst " + victimip + " or " + reflectorip
        scapy.sniff(filter = filterstring, prn = packet_callback)
  
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")

if __name__ == "__main__":
    main(sys.argv[1:])

# ./reflector --interface eth0 --victim-ip 192.168.1.10 --victim-ethernet 31:16:A9:63:FF:83 --reflector-ip 192.168.1.20 --reflector-ethernet 38:45:E3:89:B5:56
