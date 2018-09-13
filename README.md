﻿# What is KISS?
Welcome to KISS (acronym for Klesoft Is Spoofing and Sniffing), a tool for network attacks. As its name denotes, it has been created by KleSoft for research purposes. It is based on Python3 and Scapy.

# Features
 It includes features such as:
 - **Sniffing** HTTP post packets, which gets interesting form values, such as users and passwords. Those values can be customized.
 - **MITM** with ARP Spoofing, which poisons the ARP cache of the target with (gateway_ip, your_mac_addr). so that all the traffic that the target sends to the gateway is intercepted. This also done the other way round (client-->gateway and gateway-->client). It also exists the possibility of targeting the whole network *(in development)*.  
 - **DNS Spoofing**, which sends spoofed answers to DNS Queries in order to redirect domains to fake IPs, with a great customization of target domains and hosts.
 - **JS Injecting**, which injects code when the victim's browser tries to download a JavaScript file via http *(in development).*


<a href="docs/config.md">DOCS</a>
<a href="docs/verbose.md">VERBOSE</a>



# Requirements
- Python v3.7
- Scapy v2.4.0
<br><br>
> Written with [StackEdit](https://stackedit.io/).
