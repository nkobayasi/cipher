# -*- coding: utf-8 -*-

import collections
import base64
import Crypto.Cipher.AES
import Crypto.Random

AESKeySizeType = collections.namedtuple('AESKeySizeType', ['AES128', 'AES192', 'AES256'])
AESKeySize = AESKeySizeType(*Crypto.Cipher.AES.key_size)

class AESCipher(object):
    def __init__(self, key: bytes, key_size: int):
        self.block_size = Crypto.Cipher.AES.block_size
        self.key = (key + bytes(key_size))[:key_size]

    def encrypt(self, value: bytes) -> bytes:
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_EAX)
        data, mac = cipher.encrypt_and_digest(value)
        return base64.b64encode(cipher.nonce + mac + data)

    def decrypt(self, value: bytes) -> bytes:
        value = base64.b64decode(value)
        nonce = value[:self.block_size]
        mac = value[self.block_size:self.block_size*2]
        data = value[self.block_size*2:]
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(data, mac)

class AES128Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=AESKeySize.AES128)

class AES192Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=AESKeySize.AES192)

class AES256Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=AESKeySize.AES256)

def main():
    cipher = AES256Cipher(key=b'sample key')
    d = cipher.encrypt(b'abcdefghijklmnopqrstuvwxyz')
    print(d)
    print(cipher.decrypt(d))
    print(AESKeySizeType(*Crypto.Cipher.AES.key_size))
    print(AESKeySize.AES256)

if __name__ == '__main__':
    main()