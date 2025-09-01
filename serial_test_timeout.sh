#!/bin/bash

# https://claude.ai/share/427006df-f757-45a2-932d-032e069f3002
# https://claude.ai/share/4c277657-7db4-4e37-befb-afbeba84705f

# Configuration
TIMEOUT_DURATION=30  # Timeout in seconds for each operation

# Read password securely at the beginning
echo -n "Enter password (for SSH and sudo): "
read -s PASSWORD
echo  # Add newline after password input

# Cleanup function (no timeout needed - CTRL+C always works)
cleanup() {
    echo ""
    echo "CTRL+C detected! Stopping remote server and exiting..."
    sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S pkill -f /home/dibella/server.out > /dev/null 2>&1; exit"
    echo "Cleanup completed. Exiting."
    exit 0
}

# Function to stop server with timeout
stop_server() {
    echo "Stopping remote server..."
    timeout $TIMEOUT_DURATION sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S pkill -f /home/dibella/server.out > /dev/null 2>&1; exit"
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "Warning: Server stop command timed out after ${TIMEOUT_DURATION}s"
        return 1
    fi
    return 0
}

# Function to start server with timeout
start_server() {
    echo "Starting remote server..."
    timeout $TIMEOUT_DURATION sshpass -p "$PASSWORD" ssh dibella@172.104.237.69 "echo '$PASSWORD' | sudo -S nohup /home/dibella/server.out > /dev/null 2>&1 & sleep 1; exit"
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "Error: Server start command timed out after ${TIMEOUT_DURATION}s"
        return 1
    elif [ $exit_code -ne 0 ]; then
        echo "Error: Server start command failed"
        return 1
    fi
    return 0
}

# Function to run client with timeout
run_client() {
    local client_type=$1
    local client_cmd=""
    
    if [ "$client_type" = "tcp" ]; then
        echo "Running TCP client..."
        client_cmd="echo '$PASSWORD' | sudo -S ./client_tcp.out"
    else
        echo "Running MS client..."
        client_cmd="echo '$PASSWORD' | sudo -S ./client_ms.out"
    fi
    
    timeout $TIMEOUT_DURATION bash -c "$client_cmd >> $FILENAME"
    local exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        echo "Warning: Client command timed out after ${TIMEOUT_DURATION}s"
        return 1
    elif [ $exit_code -ne 0 ]; then
        echo "Warning: Client command failed with exit code $exit_code"
        return 1
    fi
    return 0
}

trap 'cleanup' SIGINT

FILENAME="serial_test_$(date +%Y%m%d_%H%M%S).csv"
echo $FILENAME

echo "MS_ENABLED;requests;payload_size;time_ms;dl_bytes;ul_bytes" > $FILENAME

# Initial server cleanup
stop_server

i=0
while true; do
    i=$((i + 1))
    echo "Iteration $i"
    
    # Start server
    if start_server; then
        
        # Generate random number 0 or 1 (50/50 chance)
        if [ $((RANDOM % 2)) -eq 0 ]; then
            run_client "tcp"
        else
            run_client "ms"
        fi
    fi
    
    # Always stop server
    stop_server
done