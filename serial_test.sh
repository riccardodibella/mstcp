#!/bin/bash

# https://claude.ai/share/427006df-f757-45a2-932d-032e069f3002

# Read password securely at the beginning
echo -n "Enter password (for SSH and sudo): "
read -s PASSWORD
echo  # Add newline after password input

trap 'echo ""; echo "CTRL+C detected! Stopping remote server and exiting..."; sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '\''$PASSWORD'\'' | sudo -S pkill -f /home/dibella/server.out > /dev/null 2>&1; exit"; echo "Cleanup completed. Exiting."; exit 0' SIGINT

FILENAME="serial_test_$(date +%Y%m%d_%H%M%S).csv"
echo $FILENAME

echo "MS_ENABLED;requests;payload_size;time_ms;dl_bytes;ul_bytes" > $FILENAME


echo "Stopping remote server..."
sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S pkill -f /home/dibella/server.out > /dev/null 2>&1; exit"


i=0
while true; do
    i=$((i + 1))
    echo "Iteration $i"
    
    # Option 1: Pass password to sudo via echo
    echo "Starting remote server..."
    sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S nohup /home/dibella/server.out > /dev/null 2>&1 & sleep 1; exit"

    # Wait a bit for server to start
    #sleep 3

    # Generate random number 0 or 1 (50/50 chance)
    if [ $((RANDOM % 2)) -eq 0 ]; then
        echo "Running TCP client..."
        echo "$PASSWORD" | sudo -S ./client_tcp.out >> $FILENAME
    else
        echo "Running MS client..."
        echo "$PASSWORD" | sudo -S ./client_ms.out >> $FILENAME
    fi


    echo "Stopping remote server..."
    sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S pkill -f /home/dibella/server.out > /dev/null 2>&1; exit"
done
