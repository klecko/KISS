---
title: Home Page
---

# What is KISS?
Welcome to KISS (acronym for Klesoft Is Spoofing and Sniffing), a tool for network attacks. As its name denotes, it has been created by Klesoft for research purposes. It is based on Python3 and Scapy.

# Features
 It includes features such as:
 - **Net Analyzer** for detecting devices in the network. It includes passive and active scanning.

 - **Sniffing** HTTP packets, which gets interesting form values, such as users, passwords, session cookies for session hijacking, etc. Those values can be customized.

 - **MITM** with ARP Spoofing, which poisons the ARP cache of the target, associating the IP of the gateway with your MAC address, so that all the traffic that the target sends to the gateway is intercepted. This is also done the other way round (traffic sent from gateway to client is also intercepted). It also exists the possibility of targeting the whole network.  

 - **DNS Spoofing**, which sends spoofed answers to DNS Queries in order to redirect domains to fake IPs, with a great customization of target domains and hosts. It also includes spoofing HTTP requests, so you won't get 404 not found as with other similar tools.

 - **URL Stalking** which shows every URL the target visits. It includes host detection for HTTPs, and complete URL detection for HTTP.

 - **JS Injecting**, which injects a JS file when the target visits a HTTP webpage. This is a doorway for many other types of attacks.



# Requirements
- Linux (KISS is unfortunately based in iptables, so it needs Linux. It can also run in Windows, but you'll need to find some firewall that does the same as iptables)
- Python v3.6+
- Scapy v2.4.0 with some custom files (comes with KISS)
