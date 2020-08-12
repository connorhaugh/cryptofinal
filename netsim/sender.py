#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from encrypt import encrypt
from netinterface import network_interface
from decrypt import decrypt
from user import User

NET_PATH = './'
OWN_ADDR = 'A'
FILENAME = "" #TODO: this variable should live in user.py

# ------------
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr>')
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

netif = network_interface(NET_PATH, OWN_ADDR)
dst = input('Type a server address: ')
user = User(netif,dst,OWN_ADDR)
user.login()
encryptionEngine = encrypt(OWN_ADDR, user.session_message_key, user.session_mac_key)
decryptionEngine = decrypt(user.session_message_key,user.session_mac_key)
receive_mode = True

while True:
	msg = input('>> ')

	if msg == 'exit' or msg == 'quit': break

	if msg == 'help':
		print("""List of commands:
Make Directory: MKD <foldername>
Remove Directory: RMD <foldername>
Get Working Directory: GWD
Change Working Directory: CWD
List Contents: LST
Upload file: UPL <filename>
Download File: DNL <filename>
Remove File from Folder: RMF <filname> <foldername>
		""")
		continue

	if msg[:3] == 'UPL':
		_, filename = msg.split()
		encryptionEngine.send_file(NET_PATH + OWN_ADDR + "/" + filename, dst, netif)

	if msg[:3] == 'DNL':
		_, filename = msg.split()
		user.filename = filename

	encryptionEngine.send(msg, dst, netif)

	while receive_mode:
		status, msg = netif.receive_msg(blocking=False)   # when returns, status is True and msg contains a message
		if status:
			label, msg = msg[:3], msg[3:]
			if (label == b'msg'):
				decryptionEngine.generate_derived_msg_key(msg)
			elif (label == b'mac'):
				decryptionEngine.generate_derived_mac_key(msg)
			elif (label == b'fil'):
				data = decryptionEngine.decrypt_msg(msg, True)
				f = open(NET_PATH + OWN_ADDR + "/" + user.filename, "wb+")
				f.write(data)
				f.close()
			elif (label == b'enc'):
				if decryptionEngine.has_keys():
					decrypt_msg = decryptionEngine.decrypt_msg(msg)
					print(decrypt_msg)
				else:
					print("keys not found")
				receive_mode = False
	receive_mode = True
