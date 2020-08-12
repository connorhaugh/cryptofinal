import Crypto,sys
from netinterface import network_interface
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import encrypt
from sessionkeygen import SessionKeyGenerator
from public_key import public_key
import json

class User:

    NET_PATH = './'         #should this be ./NETWORK ?????
    OWN_ADDR = 'B'


    def __init__(self, netif,server_addr,own_addr):
        self.OWN_ADDR=own_addr
        self.server_addr = server_addr
        self.N=0
        self.X1=0
        self.X2=0
        self.userid = ''
        self.session_message_key=''
        self.session_message_key=''
        self.netif = netif
        self.filename = ""
        self.server_pb_path= 'server_pb.pem' # Our assumption is that an attacker cannot access these
        self.client_pk_path='client_pk.pem'
        self.client_pb_path= 'client_pb.pem'
        public_key.generate_key_pair(self.client_pb_path,self.client_pk_path)
        self.userid = ''

        return

    def gen_message1(self,uid,pwd):
        #create a random nonce N
        self.N = SessionKeyGenerator.genNonce()
        #concat
        msg1_dic ={ "uid":uid, "pwd":pwd, "N": self.N, "ADDR": self.OWN_ADDR}
        msg1_json = json.dumps(msg1_dic)

        #enc using the public key of the server. TODO: encode with public key.
        msg1_enc = public_key.encrypt(self.server_pb_path,msg1_json.encode('utf-8'))
        return msg1_enc


    def login(self):

        #read in the userid and password from the command line
        print('Welcome to the Secure FTP. Please enter your username')
        self.userid=str(input())
        print('enter your password')
        pwd_str=str(input())

        #create a message to init the protocol
        enc_msg1 = self.gen_message1(self.userid,pwd_str)

        #send M1
        self.netif.send_msg(self.server_addr, enc_msg1)

        #Wait for M2
        status = None
        while (status == None):
            status, enc_msg2 = self.netif.receive_msg(blocking=True)

        pt_msg2= public_key.decrypt(self.client_pk_path,enc_msg2[0:256])
        #verify the signature
        signature = enc_msg2[256:]
        public_key.verify(self.server_pb_path,signature,pt_msg2)

        msg2_json=pt_msg2.decode('utf-8')
        msg2_dict= json.loads(msg2_json)

        if not (msg2_dict["N"]==self.N):
            print("N-related error, do not trust the server!")
            sys.exit(1)

        DH2 = SessionKeyGenerator.generate_dh2(msg2_dict["G1"],msg2_dict["G2"],msg2_dict["P1"],msg2_dict["P2"])
        self.session_message_key,self.session_mac_key = SessionKeyGenerator.calculate_keys(msg2_dict["M1"],msg2_dict["M2"], DH2['Y1'],DH2['Y2'],msg2_dict["P1"],msg2_dict["P2"])
        #create+sign+encode+send msg3

        msg3_dict = { "MA":DH2['MA'],"MB":DH2['MB'],"N":self.N,}
        msg3_pt = json.dumps(msg3_dict).encode('utf-8')

        msg3_pt_sig = public_key.sign(self.client_pk_path,msg3_pt)
        msg3_enc = public_key.encrypt(self.server_pb_path,msg3_pt)

        self.netif.send_msg(self.server_addr, msg3_enc + msg3_pt_sig)

        print('login protocol successful deriving session keys:')
        return


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
    def client_key_generation(session_message_key, session_mac_key, destination, network):
        msg_nonce = get_random_bytes(256)
        network.send_msg(destination, b'msg'+msg_nonce)
        msg_key = HMAC.new(session_message_key, msg=msg_nonce, digestmod=SHA256).digest()

        mac_nonce = get_random_bytes(256)
        network.send_msg(destination, b'mac'+mac_nonce)
        mac_key = HMAC.new(session_mac_key, msg=mac_nonce, digestmod=SHA256).digest()

        return msg_key, mac_key
