import secrets
import hashlib
import os
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding




def gen_privat_key(p):
    while True:
        gen_key = secrets.randbits(256)

        if gen_key < 2 or gen_key >= p - 1:
            continue
        if gen_key.bit_length() < 224:
            continue
        return gen_key

class DHServer:
    # Стандарт (RFC 2631) 
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

    g = 2
    def __init__(self):
        self.private_key = gen_privat_key(self.p)
        self.public_key = pow(self.g, self.private_key, self.p)
        self.client_shared = None
        self.derived_keys = {}

    def gen_secret(self, client_public_key):
        self.client_shared = pow(client_public_key, self.private_key, self.p)
    
        return self.client_shared

    def gen_key(self, length=32):
        try:
            if not self.client_shared:
                return False

            to_bytes = self.client_shared.to_bytes((self.client_shared.bit_length() + 7) // 8, 'big')

            self.derived_keys = {
                'encryption': hashlib.pbkdf2_hmac(
                    'sha256', to_bytes, b'encryption', 100000, length),
                'integrity': hashlib.pbkdf2_hmac(
                    'sha256', to_bytes, b'integrity', 100000, length)
            }
            return self.derived_keys
        except Exception:
            raise ValueError("Общий секрет не был получен")

    def encrypt_msg(self, message):
        if 'encryption' not in self.derived_keys:
            return self.gen_key()
        if isinstance(message, str):
            message = message.encode('utf-8')

        vector = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.derived_keys['encryption']), modes.CBC(vector))
        encrypt = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        pu = padder.update(message) + padder.finalize()

        encrypted = encrypt.update(pu) + encrypt.finalize()

        return vector + encrypted

    def decrypt_msg(self, encrypted_data):
        if 'encryption' not in self.derived_keys:
            return self.gen_key()

        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('latin-1')
            
        vector = encrypted_data[:16]
        ciphmsg = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.derived_keys['encryption']), modes.CBC(vector))
        decrypt = cipher.decryptor()

        padded = decrypt.update(ciphmsg) + decrypt.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        msg = unpadder.update(padded) + unpadder.finalize()

        return msg

    def create_hmac(self, data):
        if 'integrity' not in self.derived_keys:
            return self.gen_key()
        if isinstance(data, str):
            data = data.encode('utf-8')

        return hmac.new(
            self.derived_keys['integrity'],
            data,
            hashlib.sha256
        ).hexdigest()

    def verify_hmac(self, data, receive_hmac):
        if not self.derived_keys or 'integrity' not in self.derived_keys:
            self.gen_key()
        
        expect_hmac = self.create_hmac(data)
        result = hmac.compare_digest(expect_hmac, receive_hmac)

        return hmac.compare_digest(expect_hmac, receive_hmac)

dh_serv = DHServer()

