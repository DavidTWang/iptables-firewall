import os, sys

PUBLIC_INTERFACE = "em1"
PRIVATE_INTERFACE = "p3p1"
FIREWALL_IP = "192.168.0.19"

FIREWALL_INTERFACE_IP = "192.168.10.1"
INTERNAL_IP = "192.168.10.2"
SUBNET_ADDR = "192.168.10.0/24"

ALLOWED_TCP_PORTS = ["20:22", "53", "80", "443", "8006"]
ALLOWED_UDP_PORTS = ["20", "53", "67", "68", "80", "443", "8006"]
ALLOWED_ICMP_SERVICES = ["0","3","8"]

BLOCKED_TCP_PORTS = ["23", "32768:32775", "137:139", "111", "515"]
BLOCKED_UDP_PORTS = ["23", "32768:32775", "137:139"]
BLOCKED_ICMP_SERVICES = []

def reset():
	os.system("clear; iptables -F; iptables -X")
	os.system("iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT")
	print "Firewall setup reset"

def setup_system(host_type):
	if(host_type == "firewall"):
		os.system("ifconfig %s %s up" 
			% (PRIVATE_INTERFACE, FIREWALL_INTERFACE_IP))
		os.system("echo \"1\" > /proc/sys/net/ipv4/ip_forward")
		os.system("route add -net 192.168.0.0 netmask 255.255.255.0 gw %s" % FIREWALL_IP)
		os.system("route add -net %s gw %s" % (SUBNET_ADDR, FIREWALL_INTERFACE_IP))
		# os.system("iptables -t nat -A POSTROUTING -s 192.168.10.0 -o %s -j SNAT --to-source %s" 
		# 	% (PUBLIC_INTERFACE, FIREWALL_IP))
		# os.system("iptables -t nat -A PREROUTING -i %s -j DNAT --to-destination %s"
		# 	% (PUBLIC_INTERFACE, INTERNAL_IP))
		os.system("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE"
			% PUBLIC_INTERFACE)
		print "Finished setting up firewall host"

	elif(host_type == "internal"):
		os.system("ifconfig %s down" % PUBLIC_INTERFACE)
		os.system("ifconfig %s %s up" % (PRIVATE_INTERFACE, INTERNAL_IP))
		os.system("route add default gw %s" % FIREWALL_INTERFACE_IP)
		print "Finished setting up internal host. Don't forget to set nameservers."


def allow_service(service, protocol):

	if(protocol == "tcp" or protocol == "udp"):
		os.system("iptables -A FORWARD -p %s --sport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" % (protocol, service))
		os.system("iptables -A FORWARD -p %s --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT" % (protocol, service))
	elif(protocol == "icmp"):
		os.system("iptables -A FORWARD -p %s --icmp-type %s -j ACCEPT" % (protocol, service))

def block_service(service, protocol):
	if(protocol == "tcp" or protocol == "udp"):
		os.system("iptables -A FORWARD -p %s --sport %s -j DROP" % (protocol, service))
		os.system("iptables -A FORWARD -p %s --dport %s -j DROP" % (protocol, service))
	elif(protocol == "icmp"):
		os.system("iptables -A FORWARD -p %s --icmp-type %s -j DROP" % (protocol, service))

def execute_firewall():

	# =======================
	# 	DROP
	# =======================

	# Set all default policies to DROP
	os.system("iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -P FORWARD DROP")

	# Explicitly drop all packets toward the firewall
	os.system("iptables -A INPUT -d %s -j DROP" % FIREWALL_IP)

	# Drop all packets destined for the firewall host from the outside
	# os.system("iptables -A INPUT -s ! %s -d %s -j DROP" % (SUBNET_ADDR, FIREWALL_IP))

	# Drop all the packets with source ip matching the internal network
	os.system("iptables -A FORWARD -i em1 -p tcp -s %s -j DROP" % SUBNET_ADDR)

	# Block all external traffic directed to ports 32768 - 32775, 137 - 139, TCP prots 111 and 515
	os.system("iptables -A FORWARD -i em1 -p tcp -m multiport --dports 111,515,32768:32775 -j DROP")

	# Drop all TCP packets with the SYN and FIN bit set
	os.system("iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")

	# Reject Inbound SYN packets to high ports
	os.system("iptables -A FORWARD -p tcp --tcp-flags SYN SYN -dports ")

	for service in BLOCKED_TCP_PORTS:
		block_service(service, "tcp")
	for service in BLOCKED_UDP_PORTS:
		block_service(service, "udp")
	for service in BLOCKED_ICMP_SERVICES:
		block_service(service, "icmp")

	# =======================
	# 	ACCEPT
	# =======================
	# For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput"
	os.system("iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay")
	os.system("iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay")
	os.system("iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput")

	for service in ALLOWED_TCP_PORTS:
		allow_service(service, "tcp")
	for service in ALLOWED_UDP_PORTS:
		allow_service(service, "udp")
	for service in ALLOWED_ICMP_SERVICES:
		allow_service(service, "icmp")


	# ======================
	#	SECONDARY DROP
	# ======================
	# Drop incoming SYN packets from high ports
	os.system("iptables -A FORWARD -p tcp --sport 1024:65535 -j DROP")

	print "Firewall activated"

def run_script(options):
	for option in options:
		if(option == '1'):
			setup_system("firewall")
		elif(option == '2'):
			setup_system("internal")
		elif(option == '3'):
			reset()
		elif(option == '4'):
			execute_firewall()
		elif(option == '0'):
			print "Exiting..."
			sys.exit()
		else:
			print "Invalid input\n"

def main():
	while(1):
		print "COMP8006 Assignment 2"
		print "1 - Firewall computer setup"
		print "2 - Internal computer setup"
		print "3 - Reset to default"
		print "4 - Execute firewall"
		print "0 - Exit"
		print "\nSeperate multiple commands with space"

		options = raw_input("Option(s): ").split(" ")
		run_script(options)

if __name__ == '__main__':
	main()