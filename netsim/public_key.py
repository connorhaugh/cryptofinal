from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


#TODO: HANDLE FILE PATH ERRORS

class public_key:
    """Public Key Encryption and Decryption Interface that also provides signing functionality"""

    def generate_key_pair(public_key_path,private_key_path):
        key_object = RSA.generate(2048)

        private_key = key_object.export_key()
        file_out_pk = open(private_key_path, "wb")
        file_out_pk.write(private_key)
        file_out_pk.close()

        public_key = key_object.publickey().export_key()
        file_out_pb = open(public_key_path, "wb")
        file_out_pb.write(public_key)
        file_out_pb.close()
        return

    def encrypt(pb_key_path,msg):
        f = open(pb_key_path,'r')
        key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(key)
        enc_msg = cipher_rsa.encrypt(msg)

        return enc_msg

    def decrypt(pk_key_path,msg):
        private_key = RSA.import_key(open(pk_key_path).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        dec_msg = cipher_rsa.decrypt(msg)
        return dec_msg


    def sign(pk_key_path,msg):
        key = RSA.import_key(open(pk_key_path).read())
        h = SHA256.new(msg)
        signature = pkcs1_15.new(key).sign(h)
        return signature

    def verify(pb_key_path,sig,msg):
        key = RSA.import_key(open(pb_key_path).read())
        h = SHA256.new(msg)
        try:
            pkcs1_15.new(key).verify(h, sig)
        except (ValueError, TypeError):
            print ("The signature is not valid.")
