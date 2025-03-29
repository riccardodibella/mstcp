#!/bin/bash
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
gcc 09.c -DMAIN_MODE=CLIENT -o client.out
if [[ "$1" == "--local" ]]; then
    gcc 09.c -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 09.c dibella@liquigas.duckdns.org:/home/dibella
    ssh dibella@liquigas.duckdns.org 'gcc 09.c -DMAIN_MODE=SERVER -o server.out'
fi
