import logging
from charm.toolbox.pairinggroup import ZR
import sys
sys.path.append('../')
from config import PAIRING_GROUP

logger = logging.getLogger(__name__)

class Verifier:
    def __init__(self, name):
        self.name = name
        self.tpm_key = None
        logger.info(f"Initialized Verifier {self.name}")

    def generate_tpm_key(self):
        """Generate simulated TPM key for Verifier."""
        self.tpm_key = PAIRING_GROUP.random(ZR)
        logger.debug(f"Verifier {self.name}: TPM key={self.tpm_key}")