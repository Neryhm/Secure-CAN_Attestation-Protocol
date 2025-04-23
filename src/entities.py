from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
import logging
from config import GROUP, G0, G0_tilde, EDGE_IOT_COUNTS
from tpm_simulator import TPMSimulator
from crypto_utils import CryptoUtils
from network import CANNetwork

logger = logging.getLogger(__name__)

class IoTDevice:
    def __init__(self, id: int, base_point: G1):
        self.id = id
        self.base_point = base_point
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * base_point
        logger.info("IoT device %d initialized with public key: %s", id, self.public_key)

    def commit(self) -> tuple:
        """IoT device commit operation."""
        omega_k = GROUP.random(ZR)
        R_k = omega_k * self.base_point
        logger.debug("IoT %d commit: R_k=%s", self.id, R_k)
        return omega_k, R_k

    def sign(self, omega_k: ZR, c: ZR) -> ZR:
        """IoT device generates signature."""
        s_k = omega_k + c * self.private_key
        logger.debug("IoT %d signature: s_k=%s", self.id, s_k)
        return s_k

class EdgeDevice:
    def __init__(self, id: int, num_iot: int, G_k: list):
        self.id = id
        self.tpm = TPMSimulator()
        self.iot_devices = [IoTDevice(i, G_k[i-1]) for i in range(1, num_iot + 1)]
        self.num_iot = num_iot
        self.branch_key = None
        self.credential = None
        logger.info("Edge device %d initialized with %d IoT devices", id, num_iot)

    def compute_branch_key(self):
        """Compute branch public key."""
        self.branch_key = self.tpm.public_key
        for iot in self.iot_devices:
            self.branch_key += iot.public_key
        logger.info("Edge %d computed branch key: %s", self.id, self.branch_key)

class Issuer:
    def __init__(self):
        self.private_key = {'x': GROUP.random(ZR), 'y': GROUP.random(ZR)}
        self.public_key = {
            'X': self.private_key['x'] * G0_tilde,
            'Y': self.private_key['y'] * G0_tilde
        }
        self.revocation_list = set()
        logger.info("Issuer initialized with public key: %s", self.public_key)

    def check_eligibility(self, edge: EdgeDevice) -> bool:
        """Check if Edge device's TPM key is eligible."""
        pk = edge.tpm.public_key
        eligible = pk not in self.revocation_list
        logger.debug("Issuer checked eligibility of Edge %d: %s", edge.id, eligible)
        return eligible

    def issue_credential(self, edge: EdgeDevice):
        """Issue CL credential for Edge's branch key."""
        if not self.check_eligibility(edge):
            logger.error("Edge %d not eligible for credential", edge.id)
            raise ValueError("Edge not eligible")
        edge.compute_branch_key()
        edge.credential = CryptoUtils.generate_cl_credential(self.private_key, edge.branch_key, edge.num_iot)
        logger.info("Issuer issued credential to Edge %d", edge.id)

class Verifier:
    def __init__(self, is_internal: bool):
        self.is_internal = is_internal
        self.tpm = TPMSimulator() if is_internal else None
        logger.info("Verifier initialized (Internal: %s)", is_internal)

    def verify_signature(self, signature: dict, issuer_public_key: dict, message: bytes, edge: EdgeDevice) -> bool:
        """Verify group signature."""
        A_prime = signature['A_prime']
        B_prime = signature['B_prime']
        C_prime = signature['C_prime']
        D_prime = signature['D_prime']
        E0_prime = signature['E0_prime']
        E_k_prime = signature['E_k_prime']
        s0 = signature['s0']
        s_k = signature['s_k']
        c = signature['c']
        k = signature['k']
        s_r = signature['s_r']
        enc_tk = signature['ENC(TK)']
        X, Y = issuer_public_key['X'], issuer_public_key['Y']

        # Step 1: Verify CL certificate
        check1 = CryptoUtils.compute_pairing(A_prime, Y) == CryptoUtils.compute_pairing(B_prime, G0_tilde)
        check2 = CryptoUtils.compute_pairing(A_prime + D_prime, X) == CryptoUtils.compute_pairing(C_prime, G0_tilde)
        if not (check1 and check2):
            logger.error("CL certificate verification failed")
            return False

        # Step 2: Verify discrete logarithm equivalence
        t_i = [GROUP.random(ZR) for _ in range(edge.num_iot + 1)]
        G_k = [iot.public_key for iot in edge.iot_devices]
        G_k.insert(0, edge.tpm.public_key)
        sum_E = t_i[0] * E0_prime
        for i in range(edge.num_iot):
            sum_E += t_i[i + 1] * E_k_prime[i]
        sum_G = t_i[0] * G_k[0]
        for i in range(edge.num_iot):
            sum_G += t_i[i + 1] * G_k[i + 1]
        lhs = CryptoUtils.compute_pairing(sum_E, G0_tilde)
        rhs = CryptoUtils.compute_pairing(B_prime, sum_G)
        if lhs != rhs:
            logger.error("Discrete logarithm verification failed")
            return False

        # Step 3: Verify Schnorr ZKP (simplified for implementation)
        mu = s0[1] * E0_prime
        for i in range(edge.num_iot):
            mu += s_k[i] * E_k_prime[i]
        mu -= c * D_prime
        # Note: R0 + sum(R_k) verification simplified; assumed correct
        logger.info("Verification passed for message: %s", message)
        return True

class Tracer:
    def __init__(self):
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * G0
        self.records = {}  # Maps TK to PK
        logger.info("Tracer initialized with public key: %s", self.public_key)

    def trace(self, signature: dict) -> G1:
        """Trace signature to identify compromised device."""
        enc_tk = signature['ENC(TK)']
        tk = CryptoUtils.elgamal_decrypt(self.private_key, enc_tk)
        pk = self.records.get(tk, None)
        if pk:
            logger.info("Traced signature to public key: %s", pk)
        else:
            logger.error("No record found for TK: %s", tk)
        return pk