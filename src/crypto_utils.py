from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import logging
from config import GROUP, F, E, E_tilde, G0, G0_tilde, q, MAX_IOT_DEVICES

logger = logging.getLogger(__name__)

class CryptoUtils:
    @staticmethod
    def hash_to_Zq(data: bytes) -> ZR:
        """Hash data to Z_q using SHA-256."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_bytes = digest.finalize()
        value = int.from_bytes(hash_bytes, 'big') % q
        result = GROUP.init(ZR, value)
        logger.debug("Hashed to Zq: %s", result)
        return result

    @staticmethod
    def hash_to_G1(data: bytes) -> G1:
        """Hash data to a point in G1."""
        result = GROUP.hash(data, G1)
        logger.debug("Hashed to G1: %s", result)
        return result

    @staticmethod
    def generate_schnorr_signature(private_key: ZR, message: bytes, k: ZR, base_point: G1 = G0) -> tuple:
        """Generate EC-Schnorr signature."""
        R = k * base_point
        msg_hash = CryptoUtils.hash_to_Zq(message + R.serialize())
        s = k + private_key * msg_hash
        logger.debug("Generated Schnorr signature: R=%s, s=%s", R, s)
        return (R, s)

    @staticmethod
    def verify_schnorr_signature(public_key: G1, message: bytes, signature: tuple, base_point: G1 = G0) -> bool:
        """Verify EC-Schnorr signature."""
        R, s = signature
        msg_hash = CryptoUtils.hash_to_Zq(message + R.serialize())
        lhs = s * base_point
        rhs = R + msg_hash * public_key
        result = lhs == rhs
        logger.debug("Schnorr verification: %s", result)
        return result

    @staticmethod
    def generate_cl_credential(issuer_keys: dict, branch_key: G1, num_iot: int) -> dict:
        """Generate Camenisch-Lysyanskaya (CL) credential."""
        x, y = issuer_keys['private']['x'], issuer_keys['private']['y']
        t = GROUP.random(ZR)
        A = t * G0
        B = y * A
        C = x * A + t * x * y * branch_key
        D = t * y * branch_key
        E0 = t * y * G0
        E_k = [t * y * GROUP.random(G1) for _ in range(num_iot)]
        credential = {'A': A, 'B': B, 'C': C, 'D': D, 'E0': E0, 'E_k': E_k}
        logger.info("Generated CL credential for %d IoT devices: %s", num_iot, credential)
        return credential

    @staticmethod
    def elgamal_encrypt(public_key: G1, message: ZR) -> tuple:
        """ElGamal encryption."""
        r = GROUP.random(ZR)
        c1 = r * G0
        c2 = r * public_key + message * G0
        logger.debug("ElGamal encryption: c1=%s, c2=%s", c1, c2)
        return (c1, c2)

    @staticmethod
    def elgamal_decrypt(private_key: ZR, ciphertext: tuple) -> G1:
        """ElGamal decryption."""
        c1, c2 = ciphertext
        s = private_key * c1
        message = c2 - s
        logger.debug("ElGamal decryption: message=%s", message)
        return message

    @staticmethod
    def compute_pairing(a: G1, b: G2) -> 'GT':
        """Compute Type III pairing."""
        result = pair(a, b)
        logger.debug("Pairing computed: %s", result)
        return result