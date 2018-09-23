# Config File

 In order to configurate and enable the different attacks, this tool includes the file `config.ini`, which should be edited and customized. Here there's a little explanation for each value.

## NetAnalyzer
- **Enabled**: enables the scanning (0: disabled, 1: enabled).
- **Gateway**: the IP of the gateway.
- **Resolve**: enables IP resolving. Each IP address detected will be resolved in order to guess the device name (0: disabled, 1: enabled).
- **Active**: enables the active scanning, which consists in sending packets to each IP address and waiting for a response (0: disabled, 1: enabled).
- **Passive**: enables the passive scanning, which consists in sniffing the network quietly (0: disabled, 1: enabled).
- **Passive_arps_everyone**: performs a MiTM attack to the whole network in order to detect connected devices easily. Warning: this makes passive scanning very noisy.
- **Passive_timeout**: time in seconds the passive scanning will be performed. Leaving it empty means no time limit (until Ctrl-C is pressed).

## Sniff
 - **Enabled**: enables the attack (0: disabled, 1: enabled)
 - **Time_limit**: time in seconds the sniffer will remain active. Leaving it empty means no time limit (until Ctrl-C is pressed)
 - **Attributes**: location of a file containing the form keys that will be detected in HTTP post packets. Using '*' is also possible for getting every value.

## ARPS
- **Enabled**: enables the attack (0: disabled, 1: enabled).
- **Target**: the IP of the victim. Using 'everyone' is also possible, and every device will be the target. Warning: targetting 'everyone' does not support two-sides-MITM. Only client-->server is supported.
- **Gateway**: the IP of the gateway.
- **Time_limit**: time in seconds the attack will last. Leaving it empty means no time limit (until Ctrl-C is pressed).
- **Interval**: time in seconds between each ARP packet is sent.
- **Disconnect**: if set to 1, MiTM attack won't be performed. Instead, target will remain without connection (0: MiTM, 1: Disconnect).

## DNS
- **Enabled**: enables the attack (0: disabled, 1: enabled).
- **File**: location of the dns file, where the domains and the IPs they will be redirected to are established.
- **Time_limit**: time in seconds the attack will last. Leaving it empty means no time limit (until Ctrl-C is pressed).

## JS
- **Enabled**: enables the attack (0: disabled, 1: enabled).
- **File**: location of the JS file that will be injected.
- **Time_limit**: time in seconds the attack will last. Leaving it empty means no time limit (until Ctrl-C is pressed).

<br><br>
> Written with [StackEdit](https://stackedit.io/).
