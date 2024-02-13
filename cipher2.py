# -*- coding: utf-8 -*-

import base64
import Crypto.Cipher.AES
import Crypto.Random

class AESCipher(object):
    def __init__(self, key, key_size):
        self.block_size = Crypto.Cipher.AES.block_size
        self.key = (key + chr(0) * key_size)[:key_size]

    def encrypt(self, value):
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_EAX)
        data, mac = cipher.encrypt_and_digest(value)
        return base64.b64encode(cipher.nonce + mac + data)

    def decrypt(self, value):
        value = base64.b64decode(value)
        nonce = value[:self.block_size]
        mac = value[self.block_size:self.block_size*2]
        data = value[self.block_size*2:]
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(data, mac)

class AES128Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=16)

class AES192Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=24)

class AES256Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=32)