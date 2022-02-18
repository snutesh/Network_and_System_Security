# Write your script here
import os
import base64
import binascii
from Crypto import Random
from base64 import b64decode
from base64 import b64encode
from hashlib import sha3_256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import padding as padding2


class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        
        #AES Key
        # Declaration of variable
        symmetric_key = str()
        # Assignment of variable
        symmetric_key = Random.new().read(16)
        
        #RSA Key
        # Declaration of variable
        private_key_sender_rsa = str()
        public_key_sender_rsa = str()
        private_key_receiver_rsa = str()
        public_key_receiver_rsa = str()
        # Key Generation
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        # Assignment of variable
        public_key_sender_rsa = public_key.n
        private_key_sender_rsa = private_key.d
        private_key_receiver_rsa= public_key.e
        
        #ECC Key
        # Declaration of variable
        private_key_sender_ecc = str()
        public_key_sender_ecc = str()
        # Key Generation + Assignment of variable
        private_key_sender_ecc = ec.generate_private_key(ec.SECP384R1(),backend=default_backend())
        public_key_sender_ecc=private_key_sender_ecc.public_key()
        
        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this
        public_key_sender_rsa = public_key
        private_key_sender_rsa = private_key
        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        # Assigned empty string to those which does not require nonce
        nonce_aes_cbc = Random.new().read(16)
        nonce_aes_ctr = Random.new().read(8)
        nonce_encrypt_rsa = str()
        nonce_tag_rsa = str()
        nonce_aes_gcm = Random.new().read(AES.block_size)
        nonce_aes_cmac = str()
        nonce_hmac = str()
        nonce_ecdsa = str()

        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here

        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your scrit here          
            iv = nonce
            plaintext = plaintext.encode()
            # Creating objects
            aes_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            enc_obj = aes_obj.encryptor()
            pad_obj = padding.PKCS7(128).padder()
            # Padding plaintext
            pad_plaintext = pad_obj.update(plaintext) + pad_obj.finalize()
            ciphertext = enc_obj.update(pad_plaintext) + enc_obj.finalize()
                    

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here            
            plaintext= plaintext.encode()
            # Creating objects
            aes_obj = AES.new(key, AES.MODE_CTR,nonce=nonce)
            # Encryption
            ciphertext= aes_obj.encrypt(plaintext)

        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            public_key = key          
            # Creating objects
            enc_obj = PKCS1_OAEP.new(public_key)
            # Encryption
            ciphertext = enc_obj.encrypt(plaintext)

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        
        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here

        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here            
            iv = nonce           
            # Creating objects
            aes_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            unpad_obj = padding.PKCS7(128).unpadder()
            dec_obj = aes_obj.decryptor()
            # Decryption and Unpadding
            fin_cipher = dec_obj.update(ciphertext) + dec_obj.finalize()
            plaintext = unpad_obj.update(fin_cipher) + unpad_obj.finalize()
            plaintext = plaintext.decode()
            
    
        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            # Creating objects
            aes_obj = AES.new(key, AES.MODE_CTR,nonce=nonce)
            # Decryption
            plaintext = aes_obj.decrypt(ciphertext)
            plaintext= plaintext.decode()

        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            private_key = key
            # Creating objects
            dec_obj = PKCS1_OAEP.new(private_key)
            # Decryption
            plaintext = dec_obj.decrypt(ciphertext)
            key = private_key.d
        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            plaintext = plaintext.encode()
            # Creating objects
            cmac_obj = cmac.CMAC(algorithms.AES(key),backend=default_backend())
            cmac_obj.update(plaintext)
            auth_tag = cmac_obj.finalize()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            plaintext = plaintext.encode()
            # Creating objects
            hmac_obj = hmac.HMAC(key, hashes.SHA256(),backend=default_backend())
            hmac_obj.update(plaintext)
            auth_tag = hmac_obj.finalize()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            private_key = key
            plaintext = plaintext.encode()
            hash_var = int.from_bytes(sha3_256(plaintext).digest(), byteorder='big')
            auth_tag = pow(hash_var, private_key.d, private_key.n)

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            plaintext = plaintext.encode()
            auth_tag = key.sign(plaintext,ec.ECDSA(hashes.SHA256()))

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            plaintext = plaintext.encode()
            # Creating objects
            cmac_obj = cmac.CMAC(algorithms.AES(key),backend=default_backend())
            cmac_obj.update(plaintext)
            cmac_obj.verify(auth_tag)
            try:
                auth_tag_valid = True
            except cryptography.exceptions.UnsupportedAlgorithm:
                auth_tag_valid = False

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            plaintext= plaintext.encode()
            # Creating objects
            hmac_obj = hmac.HMAC(key, hashes.SHA256(),backend=default_backend())
            hmac_obj.update(plaintext)
            hmac_obj.verify(auth_tag)
            try:
                auth_tag_valid = True
            except cryptography.exceptions.UnsupportedAlgorithm:
                auth_tag_valid = False
                

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            private_key = key
            plaintext = plaintext.encode()
            hash_var = int.from_bytes(sha3_256(plaintext).digest(), byteorder='big')
            calc_hash = pow(auth_tag, private_key.e, private_key.n)
            if (hash_var == calc_hash):
                auth_tag_valid = True
            else:
                auth_tag_valid = False


        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            plaintext= plaintext.encode()
            key.verify(auth_tag, plaintext, ec.ECDSA(hashes.SHA256()))
            try:
             auth_tag_valid = True
            except cryptography.exceptions.InvalidSignature:
             auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            plaintext = plaintext.encode()
            # Creating objects
            aes_obj = AES.new(key_encrypt, AES.MODE_GCM,nonce=nonce)
            ciphertext, auth_tag = aes_obj.encrypt_and_digest(plaintext)
        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            # Creating objects
            aes_obj = AES.new(key_decrypt, AES.MODE_GCM,nonce=nonce)
            plaintext = aes_obj.decrypt_and_verify(ciphertext,auth_tag)
            plaintext = plaintext.decode()
            auth_tag_valid = True
        else:
            auth_tag_valid = False
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this
