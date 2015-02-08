#!/bin/sh

#######################################
#    	USER DEFINED SECTION
#######################################

PUBLIC_INTERFACE="em1"
PRIVATE_INTERFACE="p3p1"

INTERNAL_IP="192.168.10.2"
FIREWALL_IP="192.168.0.15"
SUBNET_ADDR="192.168.10.0/24"

################################
#    	IMPLEMENTATION
################################
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




################################################
#
#    FIREWALL IMPLEMENTATION
#
################################################


#######################################################
# Set the initial default policies 
#######################################################
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

##################################
#    PREROUTING
##################################

# For FTP and SSH services, set control conncections to "Minimum Delay" 
# and FTP data to "Maximum Throughput"
iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput


##################################
#    POSTROUTING
##################################



##################################
#    DROP
##################################
# All packets that fall through to the default rule will be dropped
# ???????

# Drop all packets destined for the firewall host from the outside
#iptables -A FORWARD -i $PUBLIC_INTERFACE -s 192.168.10.0/24 -j DROP


# Do not allow Telnet packets at all
iptables -A FORWARD -p tcp --sport 23 -j DROP
iptables -A FORWARD -p tcp --dport 23 -j DROP
iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP


# [WORKING]
# Block all external traffic directed to ports 32768 - 32775, 137 - 139, TCP prots 111 and 515
iptables -A FORWARD -p tcp -m multiport --dports 111,515,32768:32775 -j DROP

