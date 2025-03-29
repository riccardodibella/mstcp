#!/bin/bash
# https://chatgpt.com/share/67e8062d-fd34-8007-8492-0853ae27c423
gcc 08.c -DMAIN_MODE=CLIENT -o client.out
if [[ "$1" == "--local" ]]; then
    gcc 08.c -DMAIN_MODE=SERVER -DLOCAL_SERVER -o server.out
else
    scp 08.c dibella@liquigas.duckdns.org:/home/dibella
    ssh dibella@liquigas.duckdns.org 'gcc 08.c -DMAIN_MODE=SERVER -o server.out'
fi
