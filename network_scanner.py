#!/usr/bin/env python

import scapy.all as scapy
import optparse


# Read terminal commands
def get_arguments():
    parser = optparse.OptionParser()  # create object class
    # add options to use within cli
    parser.add_option("--t", "--target", dest="target", help="Target for IP address range")
    (options, arguments) = parser.parse_args()  # returns options and arguments
    if not options.target:
        # code to handle error
        parser.error("[-] Please specify a target ip range using X.X.X.X/X format , use --help for more info.")
    return options.target


ip_range = get_arguments()


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
    print("IP\t\tMAC Address\n--------------------")
    for client in results_list:
        print(client["ip"] + "\t" + client["mac"])


scan_result = scan(ip_range)
print_result(scan_result)



