#!/bin/bash
echo "$(date '+%d/%m/%Y %H:%M:%S')"
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
gcc 12.c -DMAIN_MODE=CLIENT -o client.out
if [[ "$1" == "--local" ]]; then
    gcc 12.c -g -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 12.c dibella@172.104.237.69:/home/dibella
    ssh dibella@172.104.237.69 'gcc 12.c -g -DMAIN_MODE=SERVER -o server.out'
fi
