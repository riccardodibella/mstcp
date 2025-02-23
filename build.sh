#!/bin/bash
gcc 07.c -DMAIN_MODE=CLIENT -o client.out
gcc 07.c -DMAIN_MODE=SERVER -o server.out