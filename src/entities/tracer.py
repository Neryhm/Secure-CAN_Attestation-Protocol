import logging
from charm.toolbox.pairinggroup import ZR
import sys
sys.path.append('../')
from config import PAIRING_GROUP
from crypto.ecc import generate_schnorr_proof

logger = logging.getLogger(__name__)

class Tracer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.proof = None
        logger.info("Initialized Tracer")

    def generate_keys(self, G):
        """Generate Tracer private, public keys, and Schnorr proof."""
        self.private_key = PAIRING_GROUP.random(ZR)
        self.public_key = self.private_key * G
        self.proof = generate_schnorr_proof(self.private_key, self.public_key, G)
        logger.debug(f"Tracer: Private key={self.private_key}, Public key={self.public_key}, Proof={self.proof}")