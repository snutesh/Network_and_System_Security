# Write your script here
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils


pt_file = open("original_plaintext.txt",'r')
plaintext = pt_file.read()
pt_file.close()

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""
        #AES Key
        symmetric_key = get_random_bytes(16)
        f = open("./keys/symmetric_key.txt",'w')
        f.write(symmetric_key)
        f.close()

        #RSA Keys
        private_key_sender_rsa = RSA.generate(2048)
        public_key_sender_rsa = private_key_sender_rsa.publickey
        private_key_receiver_rsa = RSA.generate(2048)
        public_key_receiver_rsa = private_key_receiver_rsa.publickey

        #EC Keys
        private_key_sender_ecc = ECC.generate(curve='P-256')
        public_key_sender_ecc = private_key_sender_ecc.public_key()


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

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""
        #AES Nonce
        f = open("./keys/symmetric_key.txt",'r')
        symmetric_key = f.read()

        aes_obj = AES.new(symmetric_key, AES.MODE_CBC)
        nonce_aes_cbc = b64encode(aes_obj.iv).decode('utf-8')

        aes_obj = AES.new(symmetric_key, AES.MODE_CTR)
        nonce_aes_ctr = b64encode(aes_obj.nonce).decode('utf-8')

        nonce_encrypt_rsa = None

        nonce_aes_cmac = None
        nonce_hmac = None
        nonce_tag_rsa = None
        nonce_ecdsa = None

        aes_obj = AES.new(symmetric_key, AES.MODE_GCM)
        nonce_aes_gcm = b64encode(aes_obj.nonce).decode('utf-8')

        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("Nonce for RSA-2048") # Do not change this
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

        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            aes_obj = AES.new(key, AES.MODE_CBC)
            ciphertext_bytes = aes_obj.encrypt(pad(plaintext, AES.block_size))
            ciphertext = b64encode(ciphertext_bytes).decode('utf-8')

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            aes_obj = AES.new(key, AES.MODE_CBC)
            ciphertext_bytes = aes_obj.encrypt(plaintext)
            ciphertext = b64encode(ciphertext_bytes).decode('utf-8')

        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            ciphertext = key.encrypt(plaintext)

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
            aes_obj = AES.new(key, AES.MODE_CBC, nonce)
            plaintext = unpad(aes_obj.decrypt(ciphertext), AES.block_size)

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            aes_obj = AES.new(key, AES.MODE_CBC, nonce)
            plaintext = aes_obj.decrypt(ciphertext)

        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            plaintext = key.decrypt(ciphertext)

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
            aes_obj = CMAC.new(key, ciphermod = AES)
            aes_obj.update(plaintext)
            auth_tag = aes_obj.digest()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            auth_tag = sha_obj.digest()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            output = sha_obj.digest()
            auth_tag = key.encrypt(output)

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            signer = DSS.new(key, 'fips-186-3')
            auth_tag = signer.sign(sha_obj)

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
            aes_obj = CMAC.new(key, ciphermod = AES)
            aes_obj.update(plaintext)
            try:
                aes_obj.verify(auth_tag)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            try:
                sha_obj.verify(auth_tag)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            output = key.decrypt(auth_tag)
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            try:
                sha_obj.verify(output)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            sha_obj = SHA3_256.new()
            sha_obj.update(plaintext)
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(sha_obj, auth_tag)
                auth_tag_valid = True
            except ValueError:
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
            aes_obj = AES.new(key_encrypt, AES.MODE_GCM, nonce)
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
            try:
                aes_obj = AES.new(key_decrypt, AES.MODE_GCM, nonce)
                plaintext = aes_obj.decrypt_and_verify(ciphertext, auth_tag)
                auth_tag_valid = True
            except (ValueError, KeyError):
                auth_tag_valid = False

        else:
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
