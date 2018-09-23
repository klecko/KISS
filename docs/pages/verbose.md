# Verbose file
KISS has a verbose file called `verbose.ini` in order to configurate which messages and warnings are going to be shown and which ones not. Here there's a little explanation and an example for each message key. Each value can be set to 0 or 1 (0: disabled, 1: enabled).

## General
|Message Key|Description|Example|
|--|--|:--:|
|verbose|General verbose. If set to 0, only errors will be printed.| - |

## JS


|Message Key|Description|Example|
|:--:|--|--|
|verbose|JS Injection verbose. If set to 0, the JS Injection module won't print anything.|<div style="text-align:center"> -</div> |
|packet_len|Warning when the length of the spoofed packet load exceed 1410 bytes. | [WARNING] Spoofed packet load length exceeded 1410 bytes. Current length: 1453|
|recv1|Info message when the first packet of a JS file transaction arrives|[ID 16802452] Recv: first packet of a JS transaction|
|recv2|Info message when the only packet of a JS file transaction arrives|[ID 16802452] Recv: first and only packet of a JS transaction|
|recv3|Info message when the last packet of a JS file transaction arrives|[ID 16802452] Recv: ultimo paquete de transaccion de JS. Finalizada transaccion de longitud 6|
|recv_seq|Info message when a packet arrives, which displays its seq number and the seq numbers of the other packets of the transaction|[ID 16802452] Recv: SEQ: 1387524 [1383294, 1384704, 1386114]|
|sent_spoofed|Info message when a spoofed answer with injected JS code is sent. Happens after the last packet of a transaction is received.|[ID 16802452] Sent: spoofed answer.|

<br><br>


> Written with [StackEdit](https://stackedit.io/).
