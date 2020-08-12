#!/usr/bin/env python3
#receiver.py

import os, sys, getopt, time
from netinterface import network_interface
from decrypt import decrypt
from server import Server
from encrypt import encrypt

NET_PATH = ''
OWN_ADDR = ''

# ------------
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
server = Server(netif, None,NET_PATH + OWN_ADDR)
server.handle_login()
decryptionEngine = decrypt(server.session_message_key, server.session_mac_key)
encryptionEngine = encrypt(OWN_ADDR, server.session_message_key, server.session_mac_key)
server.encrypt_instance=encryptionEngine
print('Server started at ' + OWN_ADDR + '...')


while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty


# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message

	label, msg = msg[:3], msg[3:]

	if (label == b'msg'):
		decryptionEngine.generate_derived_msg_key(msg)

	elif (label == b'mac'):
		decryptionEngine.generate_derived_mac_key(msg)

	elif (label == b'fil'):
		server.file = decryptionEngine.decrypt_msg(msg, True)

	elif (label == b'enc'):
		server.set_client(msg)
		if decryptionEngine.has_keys():
			decrypt_msg = decryptionEngine.decrypt_msg(msg)
			print("executing command: ", decrypt_msg)
			server.parse_command(decrypt_msg)

		else:
			print("keys not found")
