#!/usr/local/bin/python2.7
# encoding: utf-8

import base64
import Crypto.Random
import Crypto.Cipher.AES

class PKCS5PaddingMixin(object):
    def padding(self, value):
        remind = self.block_size - len(value) % self.block_size
        return value + chr(remind) * remind

    def triming(self, value):
        return value[:-ord(value[-1])]

class ZeroBytePaddingMixin(object):
    def padding(self, value):
        over = len(value) % self.block_size
        if 0 < over:
            return value + chr(0) * (self.block_size - over)
        return value

    def triming(self, value):
        return value.rstrip(chr(0))

class Cipher(object):
    pass

class AESCipher(Cipher, PKCS5PaddingMixin):
    def __init__(self, key, key_size):
        self.block_size = Crypto.Cipher.AES.block_size
        self.key = (key + chr(0) * key_size)[:key_size]

    def encrypt(self, value):
        iv = Crypto.Random.new().read(self.block_size)
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(self.padding(value)))

    def decrypt(self, value):
        value = base64.b64decode(value)
        iv = value[:self.block_size]
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CBC, iv)
        return self.triming(cipher.decrypt(value[self.block_size:]))

class AES128Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=Crypto.Cipher.AES.key_size[0])

class AES1192Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=Crypto.Cipher.AES.key_size[1])

class AES256Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=Crypto.Cipher.AES.key_size[2])
