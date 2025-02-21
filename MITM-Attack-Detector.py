# -*- coding: utf-8 -*-
"""
Created on Fri Feb  21 03:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("MITM ATTACK DETECTOR")
print(Fore.GREEN+font)

import scapy.all as scapy
import threading

# Function to check ARP packets
def monitor_arp_packets(ip_address, timeout=60):
    """
    Monitor ARP packets for signs of MITM attacks (ARP spoofing).
    
    :param ip_address: IP address to monitor for ARP spoofing.
    :param timeout: Duration to monitor in seconds.
    """
    print(f"Monitoring ARP packets for potential MITM attacks on IP: {ip_address}\n")
    
    # Dictionary to store IP -> MAC address mapping
    ip_mac_map = {}

    # Callback function to process incoming ARP packets
    def arp_callback(packet):
        if packet.haslayer(scapy.ARP):
            ip_src = packet[scapy.ARP].psrc
            mac_src = packet[scapy.ARP].hwsrc
            if ip_src == ip_address:
                if ip_src in ip_mac_map:
                    if ip_mac_map[ip_src] != mac_src:
                        print(f"[!] Potential MITM attack detected! IP: {ip_src}, MAC: {mac_src} (previous MAC: {ip_mac_map[ip_src]})")
                else:
                    print(f"[*] Monitoring ARP reply: IP: {ip_src}, MAC: {mac_src}")
                ip_mac_map[ip_src] = mac_src

    # Start sniffing the network for ARP packets
    scapy.sniff(store=0, prn=arp_callback, filter="arp", timeout=timeout)

# Main function to prompt the user and start the MITM detection
def main():
   
    # Prompt the user for an IP address to monitor for MITM attacks
    ip_address = input("Enter the target IP address to monitor:")

    # Start monitoring for ARP spoofing (MITM attacks)
    monitor_arp_packets(ip_address)

if __name__ == "__main__":
    main()
