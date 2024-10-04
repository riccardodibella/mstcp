#!/bin/bash
sudo iptables -A INPUT -p tcp --dport 19000:19999 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 19000:19999 -j DROP