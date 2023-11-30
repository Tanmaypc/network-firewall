#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import json

# Define DictOfPackets to store information about ICMP packets
DictOfPackets = {}

try:
    # Load firewall rules from the JSON file
    with open("firewall_rules.json", "r") as rule_file:
        firewall_rules = json.load(rule_file)

    # Extracting firewall parameters or using default values
    banned_ip_addresses = firewall_rules.get("BannedIPAddresses", [])
    banned_ports = firewall_rules.get("BannedPorts", [])
    banned_prefixes = firewall_rules.get("BannedPrefixes", [])
    time_threshold = firewall_rules.get("TimeThreshold", 10)
    packet_threshold = firewall_rules.get("PacketThreshold", 100)
    block_ping_attacks = firewall_rules.get("BlockPingAttacks", True)

except FileNotFoundError:
    # If the rule file is not found, set default values
    print("Rule file (firewall_rules.json) not found. Setting default values.")
    banned_ip_addresses = []
    banned_ports = []
    banned_prefixes = []
    time_threshold = 10  # seconds
    packet_threshold = 100
    block_ping_attacks = True

def firewall_handler(packet):
    # Extract packet information using Scapy
    scapy_packet = IP(packet.get_payload())

    # Check if the source IP is in the list of banned IP addresses
    if scapy_packet.src in banned_ip_addresses:
        print(f"{scapy_packet.src} is an incoming IP address banned by the firewall.")
        packet.drop()
        return

    # Check for banned destination ports in TCP and UDP layers
    if scapy_packet.haslayer(TCP):
        tcp_layer = scapy_packet.getlayer(TCP)
        if tcp_layer.dport in banned_ports:
            print(f"{tcp_layer.dport} is a destination port blocked by the firewall.")
            packet.drop()
            return

    if scapy_packet.haslayer(UDP):
        udp_layer = scapy_packet.getlayer(UDP)
        if udp_layer.dport in banned_ports:
            print(f"{udp_layer.dport} is a destination port blocked by the firewall.")
            packet.drop()
            return

    # Check if the source IP has a banned prefix
    if any(scapy_packet.src.startswith(prefix) for prefix in banned_prefixes):
        print(f"Prefix of {scapy_packet.src} is banned by the firewall.")
        packet.drop()
        return

    # Handle ICMP (ping) packets if BlockPingAttacks is True
    if block_ping_attacks and scapy_packet.haslayer(ICMP):
        icmp_layer = scapy_packet.getlayer(ICMP)
        if icmp_layer.code == 0:
            # Implement threshold for ping attacks
            if scapy_packet.src in DictOfPackets:
                time_list = DictOfPackets[scapy_packet.src]
                if len(time_list) >= packet_threshold and \
                        time.time() - time_list[0] <= time_threshold:
                    print(f"Ping by {scapy_packet.src} blocked by the firewall "
                          "(too many requests in a short span of time).")
                    packet.drop()
                    return
                else:
                    time_list.append(time.time())
            else:
                DictOfPackets[scapy_packet.src] = [time.time()]

    # Accept the packet and forward it to IPTABLES
    packet.accept()

# Create an instance of NetfilterQueue and bind it to queue number 1
nf_queue = NetfilterQueue()
nf_queue.bind(1, firewall_handler)

try:
    # Run the firewall
    nf_queue.run()
except KeyboardInterrupt:
    pass
finally:
    # Unbind the queue
    nf_queue.unbind()
