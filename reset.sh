#!/bin/bash

iptables -F

#######################################################
# Set the initial default policies 
#######################################################
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
