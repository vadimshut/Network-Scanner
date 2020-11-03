#!/usr/bin/env python
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip_range", help="IP range for scanning.Example: 192.168.1.1/24")
    options, arguments = parser.parse_args()
    if not options.ip_range:
        parser.error("[-] Please specify the IP range, use --help for more info.")
    # elif not checking_ip_range_format(options.ip_range):
    #     parser.error("[-] IP range entered incorrectly, use --help for more info.")
    print(options)
    return options


def checking_ip_range_format(ip_range):
    """FIX THIS FUNCTION!!!"""
    pass


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc,
                       "mac": element[1].hwsrc}

        clients_list.append(client_dict)
    return clients_list


def print_result(result_lists):
    print("IP\t\t\tAt MAC Address\n-----------------------------")
    for client in result_lists:
        print(f"{client['ip']}\t{client['mac']}")


if __name__ == "__main__":
    # print_result(scan(get_arguments()))
    ip = get_arguments()
    print(ip)
    scan_result = scan(ip)
    print_result(scan_result)
