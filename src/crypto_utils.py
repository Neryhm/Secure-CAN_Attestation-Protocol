from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from config import GROUP, F, E, E_tilde, G0, G0_tilde, H, q, MAX_IOT_DEVICES

logger = logging.getLogger(__name__)

class CryptoUtils:
    @staticmethod
    def hash_to_Zq(data: bytes) -> ZR:
        """Hash data to Z_q using SHA-256 and map to field element."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_bytes = digest.finalize()
        value = int.from_bytes(hash_bytes, 'big') % q
        result = GROUP.init(ZR, value)
        logger.debug("Hash to Zq: input=%s, output=%s", data.hex(), result)
        return result

    @staticmethod
    def hash_to_G1(data: bytes) -> G1:
        """Hash data to a point in G1 using Charm's hash function."""
        result = GROUP.hash(data, G1)
        logger.debug("Hash to G1: input=%s, output=%s", data.hex(), result)
        return result

    @staticmethod
    def generate_schnorr_signature(private_key: ZR, message: bytes, k: ZR, base_point: G1 = G0) -> tuple:
        """Generate EC-Schnorr signature (R, s) for message."""
        # Step 1: Compute commitment R = k * G
        R = k * base_point
        # Step 2: Compute challenge c = H(message || R)
        c = CryptoUtils.hash_to_Zq(message + R.serialize())
        # Step 3: Compute s = k + c * private_key
        s = k + c * private_key
        logger.debug("Schnorr signature: R=%s, c=%s, s=%s", R, c, s)
        return (R, s)

    @staticmethod
    def verify_schnorr_signature(public_key: G1, message: bytes, signature: tuple, base_point: G1 = G0) -> bool:
        """Verify EC-Schnorr signature."""
        R, s = signature
        # Step 1: Recompute challenge c = H(message || R)
        c = CryptoUtils.hash_to_Zq(message + R.serialize())
        # Step 2: Check s * G == R + c * public_key
        lhs = s * base_point
        rhs = R + c * public_key
        result = lhs == rhs
        logger.debug("Schnorr verification: lhs=%s, rhs=%s, result=%s", lhs, rhs, result)
        return result

    @staticmethod
    def generate_cl_credential(issuer_keys: dict, branch_key: G1, num_iot: int) -> dict:
        """Generate Camenisch-Lysyanskaya (CL) credential for branch key."""
        x, y = issuer_keys['private']['x'], issuer_keys['private']['y']
        # Step 1: Choose random t in Z_q
        t = GROUP.random(ZR)
        # Step 2: Compute credential components
        A = t * G0  # A = t * G0
        B = y * A   # B = y * A
        C = x * A + t * x * y * branch_key  # C = x * A + t * x * y * PK
        D = t * y * branch_key  # D = t * y * PK
        E0 = t * y * G0  # E0 = t * y * G0
        E_k = [t * y * GROUP.random(G1) for _ in range(num_iot)]  # E_k[i] = t * y * G_k[i]
        credential = {'A': A, 'B': B, 'C': C, 'D': D, 'E0': E0, 'E_k': E_k}
        logger.info("CL credential generated: A=%s, B=%s, C=%s, D=%s, E0=%s, E_k=%s",
                    A, B, C, D, E0, E_k)
        return credential

    @staticmethod
    def verify_cl_credential(credential: dict, issuer_public_key: dict, branch_key: G1) -> bool:
        """Verify CL credential using issuer's public key."""
        A, B, C, D, E0, E_k = credential.values()
        X, Y = issuer_public_key['X'], issuer_public_key['Y']
        # Step 1: Check e(A, Y) == e(B, G0_tilde)
        check1 = pair(A, Y) == pair(B, G0_tilde)
        # Step 2: Check e(A + D, X) == e(C, G0_tilde)
        check2 = pair(A + D, X) == pair(C, G0_tilde)
        result = check1 and check2
        logger.debug("CL credential verification: check1=%s, check2=%s, result=%s",
                     check1, check2, result)
        return result

    @staticmethod
    def elgamal_encrypt(public_key: G1, message: ZR) -> tuple:
        """ElGamal encryption of message (point in G1)."""
        # Step 1: Choose random r in Z_q
        r = GROUP.random(ZR)
        # Step 2: Compute c1 = r * G0
        c1 = r * G0
        # Step 3: Compute c2 = r * public_key + message * G0
        c2 = r * public_key + message * G0
        logger.debug("ElGamal encryption: r=%s, c1=%s, c2=%s", r, c1, c2)
        return (c1, c2)

    @staticmethod
    def elgamal_decrypt(private_key: ZR, ciphertext: tuple) -> G1:
        """ElGamal decryption to recover message point."""
        c1, c2 = ciphertext
        # Step 1: Compute s = private_key * c1
        s = private_key * c1
        # Step 2: Recover message = c2 - s
        message = c2 - s
        logger.debug("ElGamal decryption: s=%s, message=%s", s, message)
        return message

    @staticmethod
    def compute_pairing(a: G1, b: G2) -> 'GT':
        """Compute Type III pairing e: G1 x G2 -> GT."""
        result = pair(a, b)
        logger.debug("Pairing: a=%s, b=%s, result=%s", a, b, result)
        return result

    @staticmethod
    def generate_zkp_commitment(secret: ZR, base_point: G1 = G0) -> tuple:
        """Generate ZKP commitment for discrete logarithm."""
        r = GROUP.random(ZR)
        commitment = r * base_point
        logger.debug("ZKP commitment: secret=%s, r=%s, commitment=%s", secret, r, commitment)
        return r, commitment

    @staticmethod
    def generate_zkp_response(secret: ZR, r: ZR, challenge: ZR) -> ZR:
        """Generate ZKP response for Schnorr-style proof."""
        response = r + challenge * secret
        logger.debug("ZKP response: secret=%s, r=%s, challenge=%s, response=%s",
                     secret, r, challenge, response)
        return response

    @staticmethod
    def verify_zkp(public_key: G1, commitment: G1, challenge: ZR, response: ZR, base_point: G1 = G0) -> bool:
        """Verify ZKP for discrete logarithm."""
        lhs = response * base_point
        rhs = commitment + challenge * public_key
        result = lhs == rhs
        logger.debug("ZKP verification: commitment=%s, challenge=%s, response=%s, result=%s",
                     commitment, challenge, response, result)
        return result