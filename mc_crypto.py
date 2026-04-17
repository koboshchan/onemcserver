import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import os


def minecraft_sha1(*data):
    sha1 = hashlib.sha1()
    for d in data:
        sha1.update(d)

    # Minecraft's unique hex digest format
    res = int(sha1.hexdigest(), 16)
    if res >> 159:  # 160-bit hash, check sign bit
        res = -((res ^ 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) + 1)
        return f"-{res:x}"
    else:
        return f"{res:x}"


class MinecraftCipher:
    def __init__(self, shared_secret):
        # Minecraft uses AES/CFB8 with the shared secret as both key and IV
        self.encryptor = AES.new(
            shared_secret, AES.MODE_CFB, iv=shared_secret, segment_size=8
        )
        self.decryptor = AES.new(
            shared_secret, AES.MODE_CFB, iv=shared_secret, segment_size=8
        )

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.decryptor.decrypt(data)


class EncryptionContext:
    def __init__(self):
        self.key = RSA.generate(1024)
        self.public_key_der = self.key.publickey().export_key("DER")
        self.verify_token = os.urandom(4)

    def decrypt_shared_secret(self, encrypted_secret):
        cipher_rsa = PKCS1_v1_5.new(self.key)
        return cipher_rsa.decrypt(encrypted_secret, None)

    def decrypt_verify_token(self, encrypted_token):
        cipher_rsa = PKCS1_v1_5.new(self.key)
        return cipher_rsa.decrypt(encrypted_token, None)
