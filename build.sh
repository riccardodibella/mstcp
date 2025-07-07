#!/bin/bash
echo "$(date '+%d/%m/%Y %H:%M:%S')"
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
gcc 11.c -DMAIN_MODE=CLIENT -o client.out
if [[ "$1" == "--local" ]]; then
    gcc 11.c -g -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 11.c dibella@liquigas.duckdns.org:/home/dibella
    ssh dibella@liquigas.duckdns.org 'gcc 11.c -g -DMAIN_MODE=SERVER -o server.out'
fi
