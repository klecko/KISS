#!/bin/bash

BOLD="\033[1m"
CIAN="$BOLD\033[96m"
ENDC="\033[0m"

echo -e "$CIAN[KISS]$ENDC Running apt update..."
apt update
echo -e "$CIAN[KISS]$ENDC Installing python3..."
apt install python3
echo -e "$CIAN[KISS]$ENDC Installing pip..."
apt install python3-pip
echo -e "$CIAN[KISS]$ENDC Installing scapy..."
python3 -m pip install --no-cache-dir scapy
echo -e "$CIAN[KISS]$ENDC Copying custom scapy files to scapy directory..."
scapy_path=$(python3 -c "import scapy, os; print(os.path.dirname(os.path.realpath(scapy.__file__)))")
cp -r scapy_files/* $scapy_path
echo -e "$CIAN[KISS]$ENDC DONE."
