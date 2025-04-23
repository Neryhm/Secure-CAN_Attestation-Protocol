import logging
from charm.toolbox.pairinggroup import ZR
from src.config import PAIRING_GROUP

logger = logging.getLogger(__name__)

class Tracer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        logger.info("Initialized Tracer")

    def generate_keys(self, G):
        """Generate Tracer private and public keys."""
        self.private_key = PAIRING_GROUP.random(ZR)
        self.public_key = self.private_key * G
        logger.debug(f"Tracer: Private key={self.private_key}, Public key={self.public_key}")