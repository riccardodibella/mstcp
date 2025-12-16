#!/bin/bash
echo "$(date '+%d/%m/%Y %H:%M:%S')"
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
if [[ "$1" == "--local" ]]; then
    gcc 16.c -O3 -g -DMAIN_MODE=CLIENT -DLOCAL_SERVER -o client.out
else
    scp 16.c dibella@172.104.237.69:/home/dibella
    ssh dibella@172.104.237.69 'gcc 16.c -O3 -g -DMAIN_MODE=CLIENT -o client.out'
fi
# https://chatgpt.com/share/68971012-0f38-8007-afae-7fdf7c85a6a2
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to compile client."
    exit 1
fi
if [[ "$1" == "--local" ]]; then
    gcc 16.c -O3 -g -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 16.c rdibella@178.79.147.254:/home/rdibella
    ssh rdibella@178.79.147.254 'gcc 16.c -O3 -g -DMAIN_MODE=SERVER -o server.out'
fi
