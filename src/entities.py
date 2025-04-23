from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
import logging
from config import GROUP, G0, G0_tilde, EDGE_IOT_COUNTS, BASENAME
from tpm_simulator import TPMSimulator
from crypto_utils import CryptoUtils
from network import CANNetwork

logger = logging.getLogger(__name__)

class IoTDevice:
    def __init__(self, id: int, base_point: G1):
        """Initialize IoT device with key pair and base point."""
        self.id = id
        self.base_point = base_point
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * base_point
        logger.info("IoT device %d: base_point=%s, public_key=%s",
                    id, base_point, self.public_key)

    def commit(self) -> tuple:
        """Generate commitment for attestation phase."""
        omega_k = GROUP.random(ZR)
        R_k = omega_k * self.base_point
        logger.debug("IoT %d commit: omega_k=%s, R_k=%s", self.id, omega_k, R_k)
        return omega_k, R_k

    def sign(self, omega_k: ZR, c: ZR) -> ZR:
        """Generate Schnorr-style signature for ZKP."""
        s_k = omega_k + c * self.private_key
        logger.debug("IoT %d signature: omega_k=%s, c=%s, s_k=%s",
                     self.id, omega_k, c, s_k)
        return s_k

class EdgeDevice:
    def __init__(self, id: int, num_iot: int, G_k: list):
        """Initialize Edge device with TPM and IoT devices."""
        self.id = id
        self.num_iot = num_iot
        self.tpm = TPMSimulator()
        self.iot_devices = [IoTDevice(i, G_k[i-1]) for i in range(1, num_iot + 1)]
        self.branch_key = None
        self.credential = None
        logger.info("Edge %d initialized: %d IoT devices", id, num_iot)

    def compute_branch_key(self):
        """Compute branch public key as sum of TPM and IoT public keys."""
        self.branch_key = self.tpm.public_key
        for iot in self.iot_devices:
            self.branch_key += iot.public_key
        logger.info("Edge %d branch key: %s", self.id, self.branch_key)

class Issuer:
    def __init__(self):
        """Initialize Issuer with CL signature key pair."""
        self.private_key = {'x': GROUP.random(ZR), 'y': GROUP.random(ZR)}
        self.public_key = {
            'X': self.private_key['x'] * G0_tilde,
            'Y': self.private_key['y'] * G0_tilde
        }
        self.revocation_list = set()
        logger.info("Issuer initialized: public_key=%s", self.public_key)

    def check_eligibility(self, edge: EdgeDevice) -> bool:
        """Verify Edge device's TPM key eligibility."""
        pk = edge.tpm.public_key
        eligible = pk not in self.revocation_list
        logger.debug("Issuer eligibility check: Edge %d, pk=%s, eligible=%s",
                     edge.id, pk, eligible)
        return eligible

    def issue_credential(self, edge: EdgeDevice):
        """Issue CL credential to Edge device."""
        if not self.check_eligibility(edge):
            logger.error("Edge %d not eligible for credential", edge.id)
            raise ValueError("Edge not eligible")
        edge.compute_branch_key()
        edge.credential = CryptoUtils.generate_cl_credential(
            {'private': self.private_key, 'public': self.public_key},
            edge.branch_key,
            edge.num_iot
        )
        logger.info("Issuer issued credential to Edge %d: %s",
                    edge.id, edge.credential)

class Verifier:
    def __init__(self, is_internal: bool):
        """Initialize Verifier (Internal or External)."""
        self.is_internal = is_internal
        self.tpm = TPMSimulator() if is_internal else None
        logger.info("Verifier initialized: is_internal=%s", is_internal)

    def verify_signature(self, signature: dict, issuer_public_key: dict, message: bytes, edge: EdgeDevice) -> bool:
        """Verify group signature with full ZKP checks."""
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
        logger.debug("Verifying CL certificate: A_prime=%s, B_prime=%s, C_prime=%s, D_prime=%s",
                     A_prime, B_prime, C_prime, D_prime)
        check1 = CryptoUtils.compute_pairing(A_prime, Y) == CryptoUtils.compute_pairing(B_prime, G0_tilde)
        check2 = CryptoUtils.compute_pairing(A_prime + D_prime, X) == CryptoUtils.compute_pairing(C_prime, G0_tilde)
        if not (check1 and check2):
            logger.error("CL certificate verification failed: check1=%s, check2=%s",
                         check1, check2)
            return False

        # Step 2: Verify discrete logarithm equivalence
        logger.debug("Verifying discrete logarithm: E0_prime=%s, E_k_prime=%s",
                     E0_prime, E_k_prime)
        t_i = [GROUP.random(ZR) for _ in range(edge.num_iot + 1)]
        G_k = [edge.tpm.public_key] + [iot.public_key for iot in edge.iot_devices]
        # Map G1 public keys to G2 using hash_to_G2
        G_k_tilde = [CryptoUtils.hash_to_G2(GROUP.serialize(pk)) for pk in G_k]
        sum_E = t_i[0] * E0_prime
        for i in range(edge.num_iot):
            sum_E += t_i[i + 1] * E_k_prime[i]
        sum_G_tilde = t_i[0] * G_k_tilde[0]
        for i in range(edge.num_iot):
            sum_G_tilde += t_i[i + 1] * G_k_tilde[i + 1]
        lhs = CryptoUtils.compute_pairing(sum_E, G0_tilde)
        rhs = CryptoUtils.compute_pairing(B_prime, sum_G_tilde)
        if lhs != rhs:
            logger.error("Discrete logarithm verification failed: lhs=%s, rhs=%s", lhs, rhs)
            return False

        # Step 3: Verify Schnorr ZKP
        logger.debug("Verifying Schnorr ZKP: s0=%s, s_k=%s, c=%s", s0, s_k, c)
        R_sum = s0[0]
        for iot in edge.iot_devices:
            R_sum += iot.commit()[1]
        c_data = (
            GROUP.serialize(A_prime) + GROUP.serialize(B_prime) + GROUP.serialize(C_prime) +
            GROUP.serialize(D_prime) + GROUP.serialize(E0_prime) +
            b''.join(GROUP.serialize(ek) for ek in E_k_prime) +
            GROUP.serialize(R_sum) + message + str(k).encode() +
            GROUP.serialize(s_r * G0) + GROUP.serialize(s_r * edge.tpm.public_key)
        )
        computed_c = CryptoUtils.hash_to_Zq(c_data)
        if computed_c != c:
            logger.error("Schnorr ZKP verification failed: computed_c=%s, c=%s",
                         computed_c, c)
            return False

        # Step 4: Verify signature components
        mu = s0[1] * E0_prime
        for i in range(edge.num_iot):
            mu += s_k[i] * E_k_prime[i]
        mu -= c * D_prime
        logger.info("Signature verification passed: mu=%s", mu)
        return True

class Tracer:
    def __init__(self):
        """Initialize Tracer with key pair for tracing."""
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * G0
        self.records = {}
        logger.info("Tracer initialized: public_key=%s", self.public_key)

    def trace(self, signature: dict) -> G1:
        """Trace signature to identify device."""
        enc_tk = signature['ENC(TK)']
        tk = CryptoUtils.elgamal_decrypt(self.private_key, enc_tk)
        pk = self.records.get(tk, None)
        if pk:
            logger.info("Traced signature: tk=%s, pk=%s", tk, pk)
        else:
            logger.error("Trace failed: tk=%s not found", tk)
        return pk