import os

def run_script(option):
	return {
		'1': "firewall.sh",
		'2': "internal.sh",
		'3': "reset.sh",
	}.get(option, "invalid")

print "COMP8006 Assignment 2"
print "1 - Firewall computer setup"
print "2 - Internal computer setup"
print "3 - Reset to default"
option = raw_input("Option: ")
os.system("./" + run_script(option))