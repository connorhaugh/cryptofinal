from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes


class encrypt:

    def __init__(self, client_addr, session_msg_key = b'', session_mac_key = b'', sqn_number = -1):
        self.session_msg_key = session_msg_key
        self.session_mac_key = session_mac_key
        self.sqn_number = sqn_number
        self.client_addr = client_addr

    def secure_payload(self, msg_key, mac_key, msg):
        if (type(msg) != bytes):
            msg = msg.encode('utf-8')
        self.sqn_number += 1
        payload_length = len(msg)
        padding_length = AES.block_size - payload_length%AES.block_size
        mac_length = 32  # SHA256 hash value is 32 bytes long
        msg_length = 27 + AES.block_size + payload_length + padding_length + mac_length
        # create header
        header_version = b'\x01\x01'                          # protocol version 1.1
        header_type = self.client_addr.encode('utf-8')        # message type 1
        header_length = msg_length.to_bytes(20, byteorder='big') # message length (encoded on 2 bytes)
        header_sqn = self.sqn_number.to_bytes(4, byteorder='big')  # next message sequence number (encoded on 4 bytes)
        header = header_version + header_type + header_length + header_sqn

        # pad the payload and encrypt the padded payload with AES in CBC mode using a random iv
        iv = get_random_bytes(AES.block_size)
        ENC = AES.new(msg_key, AES.MODE_CBC, iv)
        padded_payload = Padding.pad(msg, AES.block_size, style='iso7816')
        encrypted_payload = ENC.encrypt(padded_payload)

        # compute the mac on the header, iv, and encrypted payload
        MAC = HMAC.new(mac_key, digestmod=SHA256)
        MAC.update(header + iv + encrypted_payload)
        mac = MAC.digest()

        return header + iv + encrypted_payload + mac

    '''
    This function is used to generate the derived message and mac keys for
    encrypting individual messages and sends message and mac nonces to the
    server so that it can generate the same keys

    ARGUMENTS:
    session_message_key - bytes: this is the session message key
    session_mac_key - bytes: this is the session mac key
    destination - char: what directory the nonces should be sent to
    network - netinterface: the network interface we are using to send the messages

    RETURNS:
    msg_key - bytes: a 256 byte message key derived from the nonce and session message key
    mac_key - bytes: a 256 byte mac key derived from the nonce and session mac key
    '''
    def client_key_generation(self, session_message_key, session_mac_key, destination, network):
        msg_nonce = get_random_bytes(256)
        network.send_msg(destination, b'msg'+msg_nonce)
        msg_key = HMAC.new(session_message_key, msg=msg_nonce, digestmod=SHA256).digest()

        mac_nonce = get_random_bytes(256)
        network.send_msg(destination, b'mac'+mac_nonce)
        mac_key = HMAC.new(session_mac_key, msg=mac_nonce, digestmod=SHA256).digest()

        return msg_key, mac_key

    def send(self, msg, destination, network):
        msg_key, mac_key = self.client_key_generation(self.session_msg_key, self.session_mac_key, destination, network)
        secure_payload = self.secure_payload(msg_key, mac_key, msg)
        network.send_msg(destination, b'enc'+secure_payload)

    def send_file(self, filename, destination, network):
        with open(filename, 'rb+') as file:
            data = file.read()
            msg_key, mac_key = self.client_key_generation(self.session_msg_key, self.session_mac_key, destination, network)
            secure_data = self.secure_payload(msg_key, mac_key, data)
            network.send_msg(destination, b'fil'+secure_data)
