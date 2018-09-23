# Config file
 aIn order to configurate and enable the different attacks, this tool includes the file `config.ini`, which should be edited and customized. Here there's a little explanation for each value.
## Sniff
 - **Enabled**: binary value for enabling or disabling the attack (0: disabled, 1: enabled)
 - **Time_limit**: time in seconds the sniffer will remain active. Leaving it empty means no time limit (until Ctrl-C is pressed)

## ARPS
- **Enabled**: binary value for enabling or disabling the attack (0: disabled, 1: enabled)
- **Target**: the IP of the victim.
- **Gateway**: the IP of the gateway. 
- **Time_limit**: time in seconds the sniffer will remain active. Leaving it empty means no time limit (until Ctrl-C is pressed).
- **Interval**: time in seconds between each ARP packet is sent.

## DNS
- **Enabled**: binary value for enabling or disabling the attack (0: disabled, 1: enabled)
- **File**: location of the dns file, where the domains and the IPs they will be redirected to are established.

<br><br>
> Written with [StackEdit](https://stackedit.io/).
