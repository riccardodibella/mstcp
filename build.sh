#!/bin/bash
gcc 08.c -DMAIN_MODE=CLIENT -o client.out
# gcc 08.c -DMAIN_MODE=SERVER -o server.out
scp 08.c dibella@liquigas.duckdns.org:/home/dibella
ssh dibella@liquigas.duckdns.org 'gcc 08.c -DMAIN_MODE=SERVER -o server.out'