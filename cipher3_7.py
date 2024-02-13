#!/usr/local/bin/python3.7
# encoding: utf-8

import base64
import collections
import Crypto.Random
import Crypto.Cipher.AES

AESKeySizeType = collections.namedtuple('AESKeySizeType', ['AES128', 'AES192', 'AES256'])
AESKeySize = AESKeySizeType(*Crypto.Cipher.AES.key_size)

class PKCS5PaddingMixin(object):
    def padding(self, value: bytes) -> bytes:
        remind = self.block_size - len(value) % self.block_size
        return value + bytes([remind] * remind)

    def triming(self, value: bytes) -> bytes:
        return value[:-value[-1]]

class ZeroBytePaddingMixin(object):
    def padding(self, value: bytes) -> bytes:
        over = len(value) % self.block_size
        if 0 < over:
            return value + bytes(self.block_size - over)
        return value

    def triming(self, value: bytes) -> bytes:
        return value.rstrip(b'\x00')

class Cipher(object):
    pass

class AESCipher(Cipher, PKCS5PaddingMixin):
    def __init__(self, key: bytes, key_size: int):
        self.block_size = Crypto.Cipher.AES.block_size
        self.key = (key + bytes(key_size))[:key_size]

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
        AESCipher.__init__(self, key, key_size=AESKeySize.AES128)

class AES1192Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=AESKeySize.AES192)

class AES256Cipher(AESCipher):
    def __init__(self, key):
        AESCipher.__init__(self, key, key_size=AESKeySize.AES256)

def main():
    cipher = AES256Cipher(key=b'sample key')
    d = cipher.encrypt(b'abcdefgh')
    print(d)
    print(cipher.decrypt(d))
    with open('sample.txt', 'rb') as inf, open('sample3.bin', 'wb') as outf:
        outf.write(cipher.encrypt(inf.read()))
    #with open('sample.bin', 'rb') as inf, open('sample.dec.txt', 'wb') as outf:
    #    outf.write(cipher.decrypt(inf.read()))

if __name__ == '__main__':
    main()
