#!/bin/sh

#######################################
#    USER DEFINED SECTION
#######################################

PUBLIC_INTERFACE="em1"
PRIVATE_INTERFACE="p3p1"
INTERNAL_IP="192.168.10.2"

################
#    MAIN
################

clear
iptables -F
iptables -X

ifconfig $PUBLIC_INTERFACE down
ifconfig $PRIVATE_INTERFACE $INTERNAL_IP up
route add default gw 192.168.10.1