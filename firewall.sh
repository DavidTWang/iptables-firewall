#!/bin/sh

#######################################
#    USER DEFINED SECTION
#######################################

PUBLIC_INTERFACE="em1"
PRIVATE_INTERFACE="p3p1"

INTERNAL_IP="192.168.10.2"
FIREWALL_IP="192.168.0.16"
SUBNET_ADDR="192.168.10.0/24"

################
#    MAIN
################
clear
iptables -F
iptables -X

ifconfig p3p1 192.168.10.1 up
echo "1">/proc/sys/net/ipv4/ip_forward
route add -net 192.168.0.0 netmask 255.255.255.0 gw $FIREWALL_IP
route add -net $SUBNET_ADDR gw 192.168.10.1

iptables -t nat -A POSTROUTING -s 192.168.10.0 -o $PUBLIC_INTERFACE -j SNAT --to-source $FIREWALL_IP
iptables -t nat -A PREROUTING -i $PUBLIC_INTERFACE -j DNAT --to-destination $INTERNAL_IP
iptables -t nat -A POSTROUTING -o $PUBLIC_INTERFACE -j MASQUERADE
