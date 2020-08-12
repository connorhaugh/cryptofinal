import os
import shutil
from Crypto.Hash import HMAC, SHA256
import encrypt
from public_key import public_key
from netinterface import network_interface
from sessionkeygen import SessionKeyGenerator
import json
import sys



class Server:

    def __init__(self, netif,encrypt_instance, server_dir):
        self.current_client = None
        self.current_client_userid = ''     #TODO: shouldn't be hard coded
        self.server_dir = server_dir
        self.encrypt_instance=encrypt_instance
        self.netif = netif
        self.current_client_dir = server_dir + "/DATA/"
        self.server_pb_path = "./server_pk.pem"
        self.server_pk_path = "./server_pb.pem"
        self.client_pb_path = "./client_pb.pem"
        public_key.generate_key_pair(self.server_pb_path,self.server_pk_path)
        with open('userdata.json') as json_file:
            data = json.load(json_file)
        self.userdict = data
        self.N = 0
        self.session_message_key=''
        self.session_mac_key=''

        # make data folder if it's not there already
        if not os.path.exists(self.current_client_dir):
          os.mkdir(self.current_client_dir)

    def set_client(self, from_msg):
        client = from_msg[2:3].decode('utf-8')
        if self.current_client == client:
            return
        self.current_client = client
        self.current_client_dir += self.current_client_userid + "/"
        if not os.path.exists(self.current_client_dir):
            os.mkdir(self.current_client_dir)

    '''used in parse_command'''
    def download_file(self, filename):
        path = self.current_client_dir + filename
        if not os.path.exists(path):
            msg_str = "This file does not exist!"
            self.encrypt_and_send(msg_str)    #send err message to client
        else:           #read in file and convert to bytes
            self.encrypt_and_send(path, True)    #send file as bytes to client
            self.encrypt_and_send("Downloaded file " + filename)

    def cwd(self, dir_arg):
        home_dir = self.server_dir + "/DATA/" + self.current_client_userid + "/"
        pathlst = self.current_client_dir.split("/")
        pathlst = pathlst[:-1]
        dirlst = dir_arg.split("/")
        for x in dirlst:
            if x == "..":
                if "/".join(pathlst) + "/" == home_dir:
                    return ""
                else:
                    pathlst = pathlst[:-1]
            elif x != ".":
                pathlst.append(x)
        path = "/".join(pathlst)
        path += "/"
        return path

    '''used in parse_command, encrypts and sends a message to the client'''
    def encrypt_and_send(self, msg_string, isFile=False):
        if isFile:
            self.encrypt_instance.send_file(msg_string, self.current_client, self.netif)
        else:
            self.encrypt_instance.send(msg_string, self.current_client, self.netif)

    '''This function takes in a decrypted command and executes it, encrypting and sending back a message to the client if necessary'''
    def parse_command(self, plaincomm):     #COMMAND NEEDS TO BE DECRYPTED BEFORE THIS IS CALLED...
        args = plaincomm.split()
        cmd = (args[0]).upper()
        if cmd == "MKD":    #make directory
            new_dir = self.current_client_dir + args[1]
            os.mkdir(new_dir)
            self.encrypt_and_send("Created directory " + new_dir)
        elif cmd == "RMD":  #remove directory
            dir_arg = args[1]
            if not os.path.exists(self.current_client_dir + dir_arg):   #if this is invalid path
                msg_str = "This folder does not exist!"
                self.encrypt_and_send(msg_str)
            else:
                shutil.rmtree(self.current_client_dir + dir_arg, ignore_errors=True)
                self.encrypt_and_send("Removed directory " + self.current_client_dir + dir_arg)
        elif cmd == "GWD":  #get working directory
            self.encrypt_and_send(self.current_client_dir)
        elif cmd == "CWD":  #change directory
            dir_arg = args[1]
            path = self.current_client_dir + dir_arg + "/"
            if not os.path.exists(path):
                msg_str = "This folder does not exist!"
                self.encrypt_and_send(msg_str)
            else:
                cwd = self.cwd(dir_arg)
                if (cwd != ""):
                    self.current_client_dir = self.cwd(dir_arg)
                    self.encrypt_and_send("Current directory: " + self.current_client_dir)
                else:
                    self.encrypt_and_send("This folder does not exist!")
        elif cmd == "LST": #list contents
            lst = os.listdir(self.current_client_dir)
            msg_str = "\t".join(lst)
            self.encrypt_and_send(msg_str)
        elif cmd == "UPL":  #form of upl FILENAME FILECONTENT
            filename = args[1]
            f = open(self.current_client_dir + filename, "wb+")
            f.write(self.file)
            f.close()
            self.encrypt_and_send("Uploaded file " + filename)
        elif cmd == "DNL":  #download file
            self.download_file(args[1])
        elif cmd == "RMF":  #rm file from folder        #in form of "rmf FILE FOLDER"
            os.remove(self.current_client_dir + args[2] + "/" + args[1])   #check formatting
            self.encrypt_and_send("Removed file " + args[1])
        else:
            msg_str =  """Invalid command. Try one of these:
Make Directory: MKD <foldername>
Remove Directory: RMD <foldername>
Get Working Directory: GWD
Change Working Directory: CWD
List Contents: LST
Upload file: UPL <filename>
Download File: DNL <filename>
Remove File from Folder: RMF <filname> <foldername>
            """
            self.encrypt_and_send(msg_str)

    # def useable_commands(self):
    #     list_of_commands = " Make Directory: MKD <foldername> \n Remove Directory: RMD <foldername> \n Get Directory GWD \n List Directory LST \n Upload file: UPL <filename> <filecontents> \n Download File: DNL <filename> "
    #     return list_of_commands
    '''
    Uses the nonce sent over from the client to generate the derived message or
    mac keys.

    ARGUMENTS:
    key - bytes: either the session message key or the session mac key
    nonce - bytes: the nonce used to generate the derived keys

    RETURNS:
    bytes: the appropriate derived key
    '''
    def generate_derived_key(self, key, nonce):
        return HMAC.new(key, msg=nonce, digestmod=SHA256).digest()




    '''
    Handles login
    '''
    def confirmlogin(self,msg):
        msg1_json = msg.decode('utf-8')
        msg1_dict=json.loads(msg1_json)

        try:
            self.userdict[msg1_dict["uid"]]
        except(KeyError):
            print("Invalid User ID: login unsucessful")
            sys,exit(1)

        pwdhash = SHA256.new(msg1_dict["pwd"].encode('utf-8')).digest().hex()

        if(self.userdict[msg1_dict["uid"]][0]==pwdhash):
            self.client_public_keypath = self.userdict[msg1_dict["uid"]][1]
            self.current_client = msg1_dict["ADDR"]
            self.current_client_userid = msg1_dict["uid"]
            self.current_client_dir += self.current_client_userid + "/"
            if not os.path.exists(self.current_client_dir):
                os.mkdir(self.current_client_dir)
            return True, msg1_dict["N"]
        else:
             print('invalid password recieved, login failed.')
             sys.exit(1)
             return False, 0


    def handle_login(self):
        print('Waiting For Login Attempt')
        status = None
        while (status == None):
        	status, lgn_msg = self.netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message

        print('received login request...')
        #deencrypt with the private key.
        lgn_msg_dec = public_key.decrypt(self.server_pk_path,lgn_msg)

        #confirm the userid,password pair matches, and return the current_usr_public_key_path
        status,self.N = self.confirmlogin(lgn_msg_dec)
        if(status):
            print('Login Completed')


        #generate the first DH message and secrets X1,X2
        DH1_dict=SessionKeyGenerator.generate_dh1()
        X1 = DH1_dict.pop("X1",None)
        X2 = DH1_dict.pop("X2",None)
        DH1_dict["N"] = self.N #append N

        DH1_final_pt = json.dumps(DH1_dict).encode('utf-8') #final json palintext

        # create signature
        DH1_final_pt_sig = public_key.sign(self.server_pk_path,DH1_final_pt)
        DH1_final_enc = public_key.encrypt(self.client_pb_path,DH1_final_pt)

        self.netif.send_msg(self.current_client, DH1_final_enc + DH1_final_pt_sig)

        status = None
        while (status == None):
        	status, msg3_enc = self.netif.receive_msg(blocking=True)

        msg3_pt= public_key.decrypt(self.server_pk_path,msg3_enc[0:256])
        msg3_sig = msg3_enc[256:]
        public_key.verify(self.client_pb_path,msg3_sig,msg3_pt)
        msg3_json=msg3_pt.decode('utf-8')
        msg3_dict= json.loads(msg3_json)

        if not (msg3_dict["N"]==self.N):
            print('error: Nonce did not match, Authentication of Message Failed')
            sys.exit(1)
        self.session_message_key,self.session_mac_key = SessionKeyGenerator.calculate_keys(msg3_dict["MA"],msg3_dict["MB"],X1,X2,DH1_dict['P1'],DH1_dict['P2'])

        return
