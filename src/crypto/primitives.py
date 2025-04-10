from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def serialize_point(point):
    return str(point)

class CryptoPrimitives:
    def __init__(self):
        self.group = PairingGroup('BN254')
        self.g1 = self.group.random(G1)
        self.g2 = self.group.random(G2)

    def hash_to_Zq(self, *args):
        data = b''.join(self.group.serialize(arg) if hasattr(arg, 'group') else str(arg).encode() for arg in args)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        hash_bytes = digest.finalize()
        hash_int = int.from_bytes(hash_bytes[:16], 'big')
        return self.group.init(ZR, hash_int % self.group.order())

    def hash_to_G1(self, data):
        return self.group.hash(str(data).encode(), G1)

    def generate_random_Zq(self):
        return self.group.random(ZR)

    def ec_multiply(self, scalar, point, group_type=G1):
        if group_type == G1:
            return scalar * point
        elif group_type == G2:
            return scalar * point
        raise ValueError("Invalid group type. Use G1 or G2.")

    def ec_add(self, point1, point2, group_type=G1):
        if group_type == G1:
            return point1 + point2
        elif group_type == G2:
            return point1 + point2
        raise ValueError("Invalid group type. Use G1 or G2.")

    def pairing(self, g1_point, g2_point):
        return pair(g1_point, g2_point)

    def schnorr_sign(self, private_key, message, base_point):
        k = self.generate_random_Zq()
        R = self.ec_multiply(k, base_point)
        c = self.hash_to_Zq(R, message)
        s = k + c * private_key
        return (s, c)

    def schnorr_verify(self, public_key, message, signature, base_point):
        s, c = signature
        R_prime = self.ec_multiply(s, base_point) - self.ec_multiply(c, public_key)
        c_prime = self.hash_to_Zq(R_prime, message)
        return c == c_prime

    def elgamal_encrypt(self, public_key, message_point, base_point):
        r = self.generate_random_Zq()
        C1 = self.ec_multiply(r, base_point)
        C2 = self.ec_multiply(r, public_key) + message_point
        return (C1, C2)

    def elgamal_decrypt(self, private_key, ciphertext, base_point):
        C1, C2 = ciphertext
        V = self.ec_multiply(private_key, C1)
        message_point = C2 - V
        return message_point

def test_primitives():
    crypto = CryptoPrimitives()
    x = crypto.generate_random_Zq()
    X = crypto.ec_multiply(x, crypto.g1)
    pairing_result = crypto.pairing(X, crypto.g2)
    print(f"Pairing result: {pairing_result != 1}")
    message = "test_message"
    sig = crypto.schnorr_sign(x, message, crypto.g1)
    assert crypto.schnorr_verify(X, message, sig, crypto.g1), "Schnorr verification failed"
    print("Schnorr signature verified successfully.")
    TK = crypto.ec_multiply(crypto.generate_random_Zq(), crypto.g1)
    enc = crypto.elgamal_encrypt(X, TK, crypto.g1)
    dec = crypto.elgamal_decrypt(x, enc, crypto.g1)
    assert dec == TK, "ElGamal decryption failed"
    print("ElGamal encryption/decryption successful.")

if __name__ == "__main__":
    test_primitives()