# To Do List

### Incoming attacks and features
- DoS Attack: probably https://www.giac.org/paper/gsec/313/naptha-type-denial-of-service-attack/100899
- JS Injecter
- Deauth Attack (maybe comes with a DHCP Spoofing attack)
- Update documentation.
- Add a little script to modify the config file from cmd.

### Incoming minor changes
- Possibility of adding a target to JS Injecter.
- HTTP Sniffer should also can sniff cookies for session hijacking.
- Maybe file dns.py should be changed to not collide with dns from scapy.
- Maybe everything imported from scapy should be changed to sc.*
- Possibility of adding subnets as targets.
- Compare packet_utilities.get_user_agents with JS_Injecter.get_attribute and other similar functions that search in packet loads. They may be repeated.
- Change lists by tuples in many situations for performance improvement.
- Maybe DNS Spoofer can only sniff DNS Queries and not DNS Answers.
- Should each function return a value depending on whether it was successful or not?
- Maybe DNS_Spoofer.has_packet_been_handled should be changed as the one of JS_Injecter.
- Maybe the possibility of changing some attributes in some classes should be added with get and set methods.


### Bug fixes
- When you disable some verbose messages for example https url stalker, [URLSTALKER] is still printed. Maybe this can be solved changing the way the verbose config is checked in log. Possible idea: with eval.
- Fucking DNS iptables with GET and POST dont work correctly.
- DNS Spoofing wikia.com to pokexperto.net some queries fails, probably because of pokexperto.net/index2.php . Investigate that.
- When you DNS Spoof, some HTTP POST Packets are not spoofed (for example login in padventures.org). I think that even if they are, it redirects to the real host.
