import time
import execute_crypto as enc
from base64 import b64encode
from base64 import b64decode
# starting time

inputfile = open("original_plaintext.txt", "rb") 
plaintext = inputfile.read()
inputfile.close()

p1 = enc.ExecuteCrypto()
symmetric_key,public_key_sender_rsa, private_key_sender_rsa,public_key_receiver_rsa, private_key_receiver_rsa,\
    public_key_sender_ecc, private_key_sender_ecc= p1.generate_keys()

nonce_aes_cbc,nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac,\
    nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm =p1.generate_nonces()

## 'AES-128-CBC'
start = time.time()
ciphertext= p1.encrypt("AES-128-CBC-ENC", symmetric_key, plaintext, nonce_aes_cbc)
plaintext= p1.decrypt("AES-128-CBC-DEC", symmetric_key, ciphertext, nonce_aes_cbc)
end = time.time()
AES_CBC =end - start
print("CBC: ",AES_CBC)

##'AES-128-CTR'
start = time.time()

ciphertext= p1.encrypt("AES-128-CTR-ENC", symmetric_key, plaintext, nonce_aes_ctr)
plaintext= p1.decrypt("AES-128-CTR-DEC", symmetric_key, ciphertext, nonce_aes_ctr)
end = time.time()
AES_CTR= end - start
print("CTR: ",AES_CTR)

########'RSA-2048-ENC'
start = time.time()
ciphertext= p1.encrypt("RSA-2048-ENC", public_key_sender_rsa, symmetric_key, nonce_encrypt_rsa)
plaintext= p1.decrypt("RSA-2048-DEC", private_key_sender_rsa, ciphertext, nonce_encrypt_rsa)
end = time.time()
RSA= end - start
print("RSA: ",RSA)

### "AES-128-CMAC-GEN"
start = time.time()
auth_tag =p1.generate_auth_tag("AES-128-CMAC-GEN", symmetric_key, plaintext, nonce_aes_cmac)
valid= p1.verify_auth_tag("AES-128-CMAC-VRF", symmetric_key, plaintext, nonce_aes_cmac, auth_tag)
end = time.time()
AES_CMAC= end - start
print("CMAC: ",AES_CMAC)

### "SHA3-256-HMAC-VRF"
start = time.time()
auth_tag =p1.generate_auth_tag("SHA3-256-HMAC-GEN", symmetric_key, plaintext, nonce_hmac)
valid= p1.verify_auth_tag("SHA3-256-HMAC-VRF", symmetric_key, plaintext, nonce_hmac, auth_tag)
end = time.time()
AES_HMAC= end - start
print("HMAC: ",AES_HMAC)


### "RSA-2048-SHA3-256-SIG-GEN"
start = time.time()
auth_tag =p1.generate_auth_tag("RSA-2048-SHA3-256-SIG-GEN", private_key_sender_rsa, plaintext, nonce_tag_rsa)
valid= p1.verify_auth_tag("RSA-2048-SHA3-256-SIG-VRF", private_key_sender_rsa, plaintext, nonce_tag_rsa, auth_tag)
end = time.time()
AES_RSA_SHA= end - start
print("RSA_SHA: ",AES_RSA_SHA)


### "ECDSA-256-SHA3-256-SIG-GEN""
start = time.time()
auth_tag =p1.generate_auth_tag("ECDSA-256-SHA3-256-SIG-GEN", private_key_sender_ecc, plaintext, nonce_ecdsa)
valid= p1.verify_auth_tag("ECDSA-256-SHA3-256-SIG-VRF", public_key_sender_ecc, plaintext, nonce_ecdsa, auth_tag)
end = time.time()
AES_ECDSA= end - start
print("ECDSA: ",AES_ECDSA)

### "ECDSA-256-SHA3-256-SIG-GEN""
start = time.time()
header = b"header"
ciphertext, auth_tag= p1.encrypt_generate_auth("AES-128-GCM-GEN", symmetric_key, header, plaintext, nonce_aes_gcm)
plaintext, auth_tag_valid =p1.decrypt_verify_auth("AES-128-GCM-VRF", symmetric_key, header, ciphertext, nonce_aes_gcm, auth_tag)
end = time.time()
AES_GCM= end - start
print("GCM: ",AES_GCM)
