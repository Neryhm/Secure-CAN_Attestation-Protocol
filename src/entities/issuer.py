import logging
from charm.toolbox.pairinggroup import ZR
from src.config import PAIRING_GROUP
from src.crypto.ecc import generate_schnorr_proof

logger = logging.getLogger(__name__)

class Issuer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.proofs = None
        logger.info("Initialized Issuer")

    def generate_keys(self, G_tilde):
        """Generate Issuer private, public keys, and Schnorr proofs."""
        x = PAIRING_GROUP.random(ZR)
        y = PAIRING_GROUP.random(ZR)
        X_tilde = x * G_tilde
        Y_tilde = y * G_tilde
        self.private_key = {'x': x, 'y': y}
        self.public_key = {'X_tilde': X_tilde, 'Y_tilde': Y_tilde}
        self.proofs = {
            'X_tilde': generate_schnorr_proof(x, X_tilde, G_tilde),
            'Y_tilde': generate_schnorr_proof(y, Y_tilde, G_tilde)
        }
        logger.debug(f"Issuer: Private key={self.private_key}, Public key={self.public_key}, Proofs={self.proofs}")