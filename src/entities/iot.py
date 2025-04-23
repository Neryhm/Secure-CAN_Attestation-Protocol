import logging
from charm.toolbox.pairinggroup import ZR
from src.config import PAIRING_GROUP
from src.crypto.ecc import generate_schnorr_proof

logger = logging.getLogger(__name__)

class IoT:
    def __init__(self, iot_id):
        self.id = iot_id
        self.private_key = None
        self.public_key = None
        self.proof = None
        self.branch_key = None
        self.credential = None
        self.tracing_token = None
        logger.info(f"Initialized IoT {self.id}")

    def generate_keys(self, G_k, k_index):
        """Generate IoT private, public keys, and Schnorr proof."""
        self.private_key = PAIRING_GROUP.random(ZR)
        self.public_key = self.private_key * G_k[k_index]
        self.proof = generate_schnorr_proof(self.private_key, self.public_key, G_k[k_index])
        logger.debug(f"IoT {self.id}: Private key={self.private_key}, Public key={self.public_key}, Proof={self.proof}")