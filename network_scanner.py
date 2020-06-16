#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) # sets the ARP.pdst field to the input ip
    # arp_request.show() # shows the details of object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # create a Ethernet class for packet construction
    # scapy.ls(scapy.Ether())  <-- lists all fields that can be used
    arp_request_broadcast = broadcast/arp_request # scapy allows combining objects using /
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print a table

    clients_list = []
    for element in answered_list: # access each element in a list
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc} # create dictionary
        clients_list.append(client_dict) # add dictionary to client_list
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n--------------------")
    for client in results_list:
        print("IP: " + client["ip"] + "\t" + "MAC: " + client["mac"])


scan_result = scan("10.0.2.1/24")
print_result(scan_result)



