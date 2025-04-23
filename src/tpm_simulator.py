from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
import logging
from config import GROUP, G0, TPM_POLICY
from crypto_utils import CryptoUtils

logger = logging.getLogger(__name__)

class TPMSimulator:
    def __init__(self):
        """Initialize TPM with key pair and policy."""
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * G0
        self.endorsement_key = GROUP.random(ZR) * G0
        self.trace_key = None  # To be set during Join Phase
        self.policy = TPM_POLICY
        logger.info("TPM initialized: public_key=%s, endorsement_key=%s",
                    self.public_key, self.endorsement_key)

    def check_policy(self) -> bool:
        """Simulate TPM policy evaluation."""
        result = self.policy['state'] == 'correct'
        logger.debug("TPM policy check: state=%s, result=%s", self.policy['state'], result)
        if not result:
            logger.error("TPM policy violation detected")
        return result

    def generate_signature(self, message: bytes, k: ZR) -> tuple:
        """Simulate TPM2_Sign command to generate Schnorr signature."""
        if not self.check_policy():
            logger.error("TPM policy check failed for signing")
            raise ValueError("Invalid TPM state")
        signature = CryptoUtils.generate_schnorr_signature(self.private_key, message, k)
        logger.info("TPM signature: message=%s, k=%s, signature=%s",
                    message.hex(), k, signature)
        return signature

    def commit(self, basename: bytes) -> tuple:
        """Simulate TPM2_Commit command for attestation."""
        # Step 1: Generate random omega_0
        omega_0 = GROUP.random(ZR)
        # Step 2: Compute R0 = omega_0 * G0
        R0 = omega_0 * G0
        # Step 3: Compute J_T = H(basename)
        J_T = CryptoUtils.hash_to_G1(basename)
        # Step 4: Compute K0 = omega_0 * J_T
        K0 = omega_0 * J_T
        logger.debug("TPM commit: basename=%s, omega_0=%s, R0=%s, J_T=%s, K0=%s",
                     basename.hex(), omega_0, R0, J_T, K0)
        return omega_0, R0, K0

    def certify_key(self) -> tuple:
        """Simulate TPM key certification."""
        cert_key = GROUP.random(ZR) * G0
        logger.debug("TPM key certification: cert_key=%s", cert_key)
        return cert_key