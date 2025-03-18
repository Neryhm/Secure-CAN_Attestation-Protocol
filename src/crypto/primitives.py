from charm.toolbox.pairinggroup import PairingGroup, G1, G2, Zr, pair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

class CryptoPrimitives:
    """Class to manage SPARK's cryptographic operations."""

    def __init__(self):
        # Initialize pairing group with BN256 curve (closest match to BN_P256)
        # See Section 6.1: "Let E be an elliptic curve defined over F..."
        self.group = PairingGroup('BN256')
        self.g1 = self.group.random(G1)  # Base point G0 in E (G1 group)
        self.g2 = self.group.random(G2)  # Base point G0_bar in E_bar (G2 group)

    def hash_to_Zq(self, *args):
        """Hash arbitrary inputs to Zq (field of integers modulo q).
        See Section 6.1: H:{0,1}^* -> Z_q"""
        # Concatenate inputs as bytes
        data = b''.join(self.group.serialize(arg) if hasattr(arg, 'group') else str(arg).encode() for arg in args)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        hash_bytes = digest.finalize()
        # Convert first 16 bytes to an integer and map to Zq
        hash_int = int.from_bytes(hash_bytes[:16], 'big')
        return self.group.init(Zr, hash_int % self.group.order())

    def hash_to_G1(self, data):
        """Hash to a point in G1. See Section 6.1: H_1:{0,1}^* -> E"""
        return self.group.hash(str(data).encode(), G1)

    def generate_random_Zq(self):
        """Generate a random element in Zq. Used for keys and nonces."""
        return self.group.random(Zr)

    # Elliptic Curve Operations
    def ec_multiply(self, scalar, point, group_type=G1):
        """Multiply a point by a scalar in G1 or G2."""
        if group_type == G1:
            return scalar * point
        elif group_type == G2:
            return scalar * point
        raise ValueError("Invalid group type. Use G1 or G2.")

    def ec_add(self, point1, point2, group_type=G1):
        """Add two points in G1 or G2."""
        if group_type == G1:
            return point1 + point2
        elif group_type == G2:
            return point1 + point2
        raise ValueError("Invalid group type. Use G1 or G2.")

    def pairing(self, g1_point, g2_point):
        """Compute Type III pairing e:G1 x G2 -> GT.
        See Section 6.1: 'equipped with a type III pairing e'"""
        return pair(g1_point, g2_point)

    # Schnorr Signature (used in Attestation Phase)
    def schnorr_sign(self, private_key, message, base_point):
        """Generate a Schnorr signature. See Section 7.3."""
        k = self.generate_random_Zq()  # Random nonce
        R = self.ec_multiply(k, base_point)  # R = k * G
        c = self.hash_to_Zq(R, message)  # Challenge c = H(R || m)
        s = k + c * private_key  # s = k + c * x
        return (s, c)

    def schnorr_verify(self, public_key, message, signature, base_point):
        """Verify a Schnorr signature."""
        s, c = signature
        R_prime = self.ec_multiply(s, base_point) - self.ec_multiply(c, public_key)
        c_prime = self.hash_to_Zq(R_prime, message)
        return c == c_prime

    # ElGamal Encryption (used in Tracing)
    def elgamal_encrypt(self, public_key, message_point, base_point):
        """Encrypt a message point using ElGamal. See Section 7.5."""
        r = self.generate_random_Zq()
        C1 = self.ec_multiply(r, base_point)  # r * G
        C2 = self.ec_multiply(r, public_key) + message_point  # r * X_T + TK
        return (C1, C2)

    def elgamal_decrypt(self, private_key, ciphertext, base_point):
        """Decrypt an ElGamal ciphertext."""
        C1, C2 = ciphertext
        V = self.ec_multiply(private_key, C1)  # x_T * r * G
        message_point = C2 - V  # (r * X_T + TK) - (r * X_T) = TK
        return message_point

def test_primitives():
    """Quick test to verify cryptographic primitives."""
    crypto = CryptoPrimitives()
    
    # Test ECC and pairing
    x = crypto.generate_random_Zq()
    X = crypto.ec_multiply(x, crypto.g1)
    pairing_result = crypto.pairing(X, crypto.g2)
    print(f"Pairing result: {pairing_result != 1}")  # Should be non-trivial
    
    # Test Schnorr signature
    message = "test_message"
    sig = crypto.schnorr_sign(x, message, crypto.g1)
    assert crypto.schnorr_verify(X, message, sig, crypto.g1), "Schnorr verification failed"
    print("Schnorr signature verified successfully.")
    
    # Test ElGamal
    TK = crypto.ec_multiply(crypto.generate_random_Zq(), crypto.g1)
    enc = crypto.elgamal_encrypt(X, TK, crypto.g1)
    dec = crypto.elgamal_decrypt(x, enc, crypto.g1)
    assert dec == TK, "ElGamal decryption failed"
    print("ElGamal encryption/decryption successful.")

if __name__ == "__main__":
    test_primitives()