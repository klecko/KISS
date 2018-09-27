# To Do List

### Incoming attacks and features
- DoS Attack: probably [this one](https://www.giac.org/paper/gsec/313/naptha-type-denial-of-service-attack/100899)
- JS Injecter (almost done)
- Deauth Attack (maybe comes with a DHCP Spoofing attack)
- Add a little script to modify the config file from cmd.
- Update documentation.

### Incoming minor changes
- Beautiful JS log please
- Think about making every 'packet load' attribute bytes, str or both.
- Maybe file dns.py should be changed to not collide with dns from scapy.
- Maybe everything imported from scapy should be changed to sc.*
- Possibility of adding subnets as targets.
- Compare packet_utilities.get_user_agents with JS_Injecter.get_attribute and other similar functions that search in packet loads.

### Bug fixes
- JS Injecting seems not to work when chunked + gzip or when gzip fails.
- Fucking DNS iptables with HTTP GET and POST dont work correctly.
- [Hasn't happened in a while] DNS Spoofing wikia.com to pokexperto.net some queries fails, probably because of pokexperto.net/index2.php. Investigate that.
- When you DNS Spoof, some HTTP POST Packets are not spoofed (for example login in padventures.org). I think that even if they are, it redirects to the real host.
