#!/bin/bash

BOLD="\033[1m"
CIAN="$BOLD\033[96m"
ENDC="\033[0m"

echo -e "$CIAN[KISS]$ENDC Running apt update..."
apt update
echo -e "\n$CIAN[KISS]$ENDC Installing python3..."
apt install python3
echo -e "\n$CIAN[KISS]$ENDC Installing python3-distutils..."
apt install python3-distutils

echo -e "\n$CIAN[KISS]$ENDC Installing scapy..."
mkdir tmp
wget -O tmp/master.zip --trust-server-names https://github.com/secdev/scapy/archive/master.zip 
unzip tmp/master.zip -d tmp/
cd tmp/scapy-master/
python3 setup.py install
cd ../..
rm -r tmp

echo -e "\n$CIAN[KISS]$ENDC Copying custom scapy files to scapy directory..."
scapy_path=$(python3 -c "import scapy, os; print(os.path.dirname(os.path.realpath(scapy.__file__)))")
cp -r scapy_files/* $scapy_path
echo -e "\n$CIAN[KISS]$ENDC DONE."
