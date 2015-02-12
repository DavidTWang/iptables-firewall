import os, sys
from subprocess import PIPE, Popen

PUBLIC_INTERFACE = "em1"
PRIVATE_INTERFACE = "p3p1"

EXTERNAL_IP = "192.168.0.21"
FIREWALL_IP = "192.168.0.20"
FIREWALL_INTERFACE_IP = "192.168.10.1"
INTERNAL_IP = "192.168.10.2"
SUBNET_ADDR = "192.168.10.0/24"

ALLOWED_TCP_PORTS = ["20:22", "53", "80", "443", "8006"]
ALLOWED_UDP_PORTS = ["20", "53", "67", "68", "80", "443", "8006"]
ALLOWED_ICMP_SERVICES = ["0","3","8"]

BLOCKED_TCP_PORTS = ["23"]
BLOCKED_UDP_PORTS = ["23"]
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
	# 	SETUP
	# =======================

	# =======================
	# 	DROP
	# =======================

	# Set all default policies to DROP
	os.system("iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -P FORWARD DROP")

	# Explicitly drop all packets toward the firewall
	os.system("iptables -A -p tcp FORWARD -d %s -j DROP" % FIREWALL_IP)

	# Drop all packets destined for the firewall host from the outside
	# os.system("iptables -A INPUT -s ! %s -d %s -j DROP" % (SUBNET_ADDR, FIREWALL_IP))

	# Drop all the packets with source ip matching the internal network
	os.system("iptables -A FORWARD -i em1 -s %s -j DROP" % SUBNET_ADDR)

	# Block all external traffic directed to ports 32768 - 32775, 137 - 139, TCP prots 111 and 515
	os.system("iptables -A FORWARD -i em1 -p tcp -m multiport --dports 111,515,32768:32775 -j DROP")

	# Drop all TCP packets with the SYN and FIN bit set
	os.system("iptables -A FORWARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP")

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
	os.system("iptables -A FORWARD -i em1 -p tcp --dport 1024:65535 -j DROP")
	os.system("iptables -A FORWARD -i em1 -p udp --dport 1024:65535 -j DROP")

	print "Firewall activated"

def log_test(title, command):
	os.system("echo \"%s\" >> test_results.log" % title)
	os.system("echo \"Command Used: %s\" >> test_results.log" % command)
	os.system("%s 2>temp.2 1>temp.1" % command)
	os.system("cat temp.1 temp.2 >> test_results.log; rm -f temp.*")
	os.system("echo ======================= >> test_results.log")
	raw_input("Press enter to continue")

def run_external_test():
	tests = dict([
		("Test 1: TCP Outgoing packet (Accept)",
			"hping3 %s -S -s 8006 -c 5 -k" % INTERNAL_IP),
		("Test 2: TCP Outgoing packet (Block)",
			"hping3 %s -S -s 7006 -c 5 -k" % INTERNAL_IP),
		("Test 3: UDP Outgoing packet (Accept)",
			"hping3 %s -s 8006 --udp -c 5 -k" % INTERNAL_IP),
		("Test 4: UDP Outgoing packet (Block)",
			"hping3 %s -s 7006 --udp -c 5 -k" % INTERNAL_IP),
		("Test 5: ICMP Outgoing packet (Accept)",
			"hping3 %s --icmp -C 8" % INTERNAL_IP),
		("Test 6: ICMP Outgoing packet (Block)",
			"hping3 %s --icmp -C 15" % INTERNAL_IP),
		("Test 7: Drop packets destined for the firewall host from outside",
			"hping3 %s -S -c 5" % FIREWALL_IP),
		("Test 8: Drop packets from outside matching your internal network",
			"hping3 %s -S -p 80 -c 5 -a 192.168.10.5" % INTERNAL_IP),
		("Test 9: Accept fragmented packets",
			"hping3 %s -S -f -d 256 -c 5 -p 8006 -k" % INTERNAL_IP),
		("Test 10: Drop SYN FIN packets",
			"hping3 %s -S -F -p 80 -c 5 -k" % INTERNAL_IP),
		("Test 11: Do not allow Telnet packets",
			"hping3 %s -S -s 23 -c 5 -k" % INTERNAL_IP),
		("Test 12: Block external traffic on ports 32768:32775",
			"hping3 %s -S -p 32768 -c 7" % INTERNAL_IP),
		("Test 13: Set SSH services to 'Minimum Delay'",
			"hping3 %s -S -p 22 -c 5 -k" % INTERNAL_IP),
		("Test 14: Set FTP-D services to 'Maximum-throughput'",
			"hping3 %s -S -p 20 -c 5 -k" % INTERNAL_IP)
	])
	for title, command in tests.items():
		log_test(title, command)

	# print "Test 1: TCP Outgoing packet (Accept)"
	# os.system("hping3 %s -S -s 8006 -c 5 >> ext_Test1.log" % INTERNAL_IP)
	# raw_input("Press enter to continue")

	# print "Test 2: TCP Outgoing packet (Block)"
	# os.system("hping3 %s -S -s 7006 -c 5 >> ext_Test2.log" % INTERNAL_IP)
	# raw_input("Press enter to continue")

	# print "Test 3: UDP Outgoing packet"
	# os.system("hping3 %s -S -s 8006 --udp -c 5 >> ext_Test3.log" % INTERNAL_IP)
	# raw_input("Press enter to continue")


	# print "Test 5: ICMP Outgoing packet"
	# os.system("")


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
		elif(option == '5'):
			run_internal_test()
		elif(option == '6'):
			run_external_test()
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
		print "5 - Run tests (From Internal computer)"
		print "6 - Run tests (From External computer)"
		print "0 - Exit"
		print "\nSeperate multiple commands with space"

		options = raw_input("Option(s): ").split(" ")
		run_script(options)

if __name__ == '__main__':
	main()