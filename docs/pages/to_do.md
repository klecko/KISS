# To Do List

**READ:** KISS is not under development anymore.

### Incoming attacks and features
- DoS Attack: probably [this one](https://www.giac.org/paper/gsec/313/naptha-type-denial-of-service-attack/100899)
- Deauth Attack (maybe comes with a DHCP Spoofing attack)
- Add a little script to modify the config file from cmd.
- Add JS Documentation in code, Update general documentation in github.

### Incoming minor changes
- Maybe file dns.py should be changed to not collide with dns from scapy.
- Maybe everything imported from scapy should be changed to sc.*
- Possibility of adding subnets as targets.

### Known bugs
- Couldn't figure out how to make iptables match both http GET and POST packets, so I think POST packets are not being spoofed.
- [Hasn't happened in a while] DNS Spoofing wikia.com to pokexperto.net some queries fails, probably because of pokexperto.net/index2.php. Investigate that.
- **Nowadays http protocol is barely used, being replaced by HTTPS and also QUIC (I was surprised my mobile phone was using it) so this tool is quite obsolete.**
