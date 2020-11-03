#!/usr/bin/env python
import scapy.all as scapy
import argparse
from colorama import init, Fore, Back, Style


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP range / IP for scanning.Example: 192.168.1.1/24")
    options = parser.parse_args()
    if not options.target:
        parser.error(Fore.RED + "[-]" + Fore.GREEN + "Please specify the IP range, use --help for more info.")
    # elif not checking_ip_range_format(options.ip_range):
    #     parser.error("[-] IP range entered incorrectly, use --help for more info.")
    return options.target


def checking_ip_range_format():
    """FIX THIS FUNCTION!!!"""
    pass


def print_result(func):
    def wrapper(*args, **kwargs):
        print(
            Fore.YELLOW + f"{'-' * 33}\nIP\t\tAt MAC Address\n{'-' * 33}")
        result_list = func(*args, **kwargs)
        for client in result_list:
            print(f"{client['ip']}\t{client['mac']}")
        print(Fore.YELLOW + f"{'-' * 33}\n")
    return wrapper


@print_result
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = ether_broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
    return clients_list


if __name__ == "__main__":
    init(autoreset=True)
    scan(get_arguments())

