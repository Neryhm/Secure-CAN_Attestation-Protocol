import logging
from charm.toolbox.pairinggroup import ZR
from src.config import PAIRING_GROUP

logger = logging.getLogger(__name__)

class IoT:
    def __init__(self, iot_id):
        self.id = iot_id
        self.private_key = None
        self.public_key = None
        logger.info(f"Initialized IoT {self.id}")

    def generate_keys(self, G_k, k_index):
        """Generate IoT private and public keys."""
        self.private_key = PAIRING_GROUP.random(ZR)
        self.public_key = self.private_key * G_k[k_index]
        logger.debug(f"IoT {self.id}: Private key={self.private_key}, Public key={self.public_key}")