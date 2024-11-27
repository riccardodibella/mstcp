#!/bin/bash
gcc 05.c -DMAIN_MODE=CLIENT -o client.out
gcc 05.c -DMAIN_MODE=SERVER -o server.out