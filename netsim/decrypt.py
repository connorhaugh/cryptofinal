
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding
from Crypto import Random


class decrypt:
    def __init__(self, session_msg_key = b'', session_mac_key = b'', rcvsqn = -1):
        self.session_msg_key = session_msg_key
        self.session_mac_key = session_mac_key
        self.rcvsqn = rcvsqn
        self.encrypt_key = b''
        self.mac_key = b''

    def decrypt_msg(self, msg, isFile = False):
        header = msg[0:27]                              # header is 9 bytes long
        iv = msg[27:27+AES.block_size]                   # iv is AES.block_size bytes long
        mac = msg[-32:]                                # last 32 bytes is the mac
        encrypted_payload = msg[27+AES.block_size:-32]  # encrypted payload is between iv and mac
        header_version = header[0:2]                   # version is encoded on 2 bytes
        header_type = header[2:3]                      # type is encoded on 1 byte
        header_length = header[3:23]                    # msg length is encoded on 2 bytes
        header_sqn = header[23:27]


        if len(msg) != int.from_bytes(header_length,byteorder='big'):
            return "Warning: Message length value in header is wrong!"

        snd_number = int.from_bytes(header_sqn, byteorder='big')
        if snd_number - self.rcvsqn != 1:
            return "Error: Message sequence number is too old!"
        else:
            self.rcvsqn = self.rcvsqn + 1

        MAC = HMAC.new(self.mac_key, digestmod=SHA256)
        MAC.update(header + iv + encrypted_payload)
        computed_mac = MAC.digest()
        if (computed_mac != mac):
            return "Error: MAC verification failed!"
            # TODO: request a new message

        ENC = AES.new(self.encrypt_key, AES.MODE_CBC, iv)
        try:
            padded_payload = ENC.decrypt(encrypted_payload)
            payload = Padding.unpad(padded_payload, AES.block_size, style='iso7816')
        except Exception as e:
            return "Error: Decryption failed!"
            # TODO: request a new message

        self.encrypt_key = b''
        self.mac_key = b''

        if isFile:
            return payload
        else:
            return payload.decode('utf-8')

    '''
    Uses the nonce sent over from the client to generate the derived message or
    mac keys.

    ARGUMENTS:
    key - bytes: either the session message key or the session mac key
    nonce - bytes: the nonce used to generate the derived keys

    RETURNS:
    bytes: the appropriate derived key
    '''
    def generate_derived_msg_key(self, nonce):
        self.encrypt_key = HMAC.new(self.session_msg_key, msg=nonce, digestmod=SHA256).digest()

    def generate_derived_mac_key(self, nonce):
        self.mac_key = HMAC.new(self.session_mac_key, msg=nonce, digestmod=SHA256).digest()

    def has_keys(self):
        return self.encrypt_key != b'' and self.mac_key != b''
