#!/bin/bash
gcc 06.c -DMAIN_MODE=CLIENT -o client.out
gcc 06.c -DMAIN_MODE=SERVER -o server.out