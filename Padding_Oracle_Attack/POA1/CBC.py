from Crypto.Cipher import AES
from os import urandom
import string

from flag import FLAG

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '!_{}'
assert all(i in chars for i in FLAG.decode())

def pad(msg, block_size):
    pad_len = 16 - len(msg) % block_size
    return msg + bytes([pad_len])*pad_len

def encrypt(key):
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(pad(FLAG,16)) ).hex()
    
    
def decrypt(enc,key):
    enc = bytes.fromhex(enc)
    iv = enc[:16]
    ciphertext = enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if all(i == pad_len for i in decrypted[-pad_len:]):
        return b'Decrypted successfully.'
    else:
        return b'Incorrect padding.'

if __name__ == '__main__':
    key = urandom(16)
    while True:
        choice = input()
        if choice == 'encrypt':
            print(encrypt(key))
        elif choice == 'decrypt':
            c = input('Ciphertext: ')
            try:
                print(decrypt(c,key))
            except:
                continue

