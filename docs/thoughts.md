## Writing for the future
I'm writing this four months after I stopped developing KISS, because there are a few things I don't want to forget about this project. Do not expect any kind of text coherence or cohesion, I am writing just as I think.

Developing KISS was very interesting for me to learn a lot about network protocols and basic network attacks. It started with a necessity. I wanted to learn how to perform a DNS Spoofing attack, but everytime I tried it didn't work correctly. Later I realized it was because most DNS Spoofing only spoof DNS packets, and not HTTP get requests, so the request asked for the original domain to the spoofed domain, who obviously answered with a 404 not found. My DNS Spoofer spoofs both DNS and HTTP get requests, so it redirects correctly.

However, I think I didn't do it the correct way. The two main errors I had was relying on iptables, and using Scapy for high level things such as JS Injecting. Both JS Injecting and DNS Spoofing sniff packets, modify and forward some of them, answer some others. This means some packets couldn't be forwarded by the operating system. But ARPS actually enables IP forwarding, so every packet is forwarded. What I did was using iptables in order to drop some packets, so KISS could do whatever it needed to do. For JS Injecting, every packet containing `ype: text/html` was dropped (the first packet of a HTTP answer, so I could inject code there), and for DNS Spoofing, every packet going to port 53 or containing `GET` was dropped (DNS Queries, so I could answer or forward them, and HTTP Get requests, so I could modify the host).

This gave me a lot of problems. I couldn't find the way to match multiple strings with iptables, so I think POST requests are just forwarded without spoofing. Other problem was that I actually sniffed my own packets after having sending them, and also some repeated packets, so I had to save the checksum of every packet in order to forward those ones.

JS Injecting has a big problem: it can only inject code in some situations, in many others it just forwards the packet. This is because most packets have gzip compression. I can only inject data to those packets if the whole content arrives in one single packet, so I have all the data and can decompress it, add the JS code, compress it, modify length headers and send it. On the other side, if the data in the first packet is not complete, decompressing it fails, and I can do nothing except forwarding it. I thought about not decompressing it and just injecting my compressed data. It seemed to work, data was sent correctly, and arrived correctly, but as it contained two gzipped files, browsers only displayed the first one (my injected data), so it was not useful. Even injecting data when I could was quite difficult, as I had to take care of content encoding (only gzip implemented), transfer encoding (only chunked implemented), modifying chunks headers length, modifying packet headers, etc.

Definitely, using a low-level module such as Scapy for this was not a good idea. For JS Injecting and HTTP get requests spoofing it would have been much better using something like a proxy, which is higher-level software, easier and more reliable.

The rest of the modules were easier:

Net Analyzer has two possible analysis: active and passive. Active analysis consists in broadcasting an ARP packet and waiting for a response of the devices. Passive analysis consists in sniffing every packet sent over the network and getting the ip of the devices.

Url Stalker sniffs every packet going to port 80 or 443. If going to port 80, as the packet is raw, it simply reads the host header of the packet. Port 443 was a bit more tricky, but I discovered every of those packets read by scappy had a layer called `TLS_Ext_ServerName`, with an attribute called `servername` which is raw, so it just reads it.

ARP Spoofer just sends ARP packets to the target and to the gateway to poison the ARP tables. However, it took me a lot of attempts to learn a bit about packet layers and ARP protocol.
If I router is X, and I want to poison a single victim with ip Y, I ask him `who is Y? I am X` (ARP request). That way, he answers me and, what is important, saves the IP address of the router and my MAC address on his ARP table.
However, how could I poison the entire network? I can not send a packet to everyone in the network continuously, as it would generate too much noise. Sending `who is 255.255.255.255? I am X` didn't work, I think the packet was not even broadcasted, and if it was, it was ignored. What finally worked was broadcasting `I am X` (ARP answer), so everyone saved the IP address of the router and my MAC on his ARP table. For broadcasting, I had to add an Ether layer (layer 2) with destination set to `ff:ff:ff:ff:ff:ff`.

The Sniffing module sniffs every HTTP packet. If it is a POST message, it gets all the sent data. Else, if get_every_cookie was set to 1, it gets every cookie.

Talking a bit more about problems, KISS is quite useless if ARP Spoofing doesn't work, as many others modules depend on it. Even if ARP Spoofing works, nowadays http protocol is barely used, being replaced by HTTPS and also QUIC (I was surprised my mobile phone was using it) so this tool is quite obsolete.

Another thing is that I had to modify Scapy several times. I fixed some things in send function related to packet fragmentation, because it failed when I tried to send a "big" packet. Also, I had to modify the sniff function in order to include a way to stop sniffing, becuase originally the only way was with a timeout.

Even with all those mistakes and obstacles, I think it was completely worth it.
