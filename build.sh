#!/bin/bash
echo "$(date '+%d/%m/%Y %H:%M:%S')"
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
gcc 14.c -g -DMAIN_MODE=CLIENT -o client.out
# https://chatgpt.com/share/68971012-0f38-8007-afae-7fdf7c85a6a2
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to compile client."
    exit 1
fi
if [[ "$1" == "--local" ]]; then
    gcc 14.c -g -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 14.c dibella@172.104.237.69:/home/dibella
    ssh dibella@172.104.237.69 'gcc 14.c -g -DMAIN_MODE=SERVER -o server.out'
fi
