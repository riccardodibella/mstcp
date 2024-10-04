#!/bin/bash
sudo iptables -A INPUT -p tcp --dport 19000:19999 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 19000:19999 -j DROP
# disable segmentation offloading 
# https://www.ibm.com/docs/en/linux-on-systems?topic=offload-tcp-segmentation
sudo ethtool -K eth0 tx off sg off tso off