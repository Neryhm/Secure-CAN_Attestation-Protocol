import logging
from src.crypto.tpm_sim import generate_tpm_key, create_tpm_policy

logger = logging.getLogger(__name__)

class Edge:
    def __init__(self, edge_data):
        self.id = edge_data['id']
        self.iots = edge_data['iots']
        self.tpm_key = edge_data['tpm_key']
        self.public_key = edge_data['public_key']
        self.tpm_policy = edge_data['tpm_policy']
        logger.info(f"Initialized Edge {self.id} with {len(self.iots)} IoT devices")

    def generate_keys(self, G0):
        """Generate TPM key and public key."""
        self.tpm_key = generate_tpm_key()
        self.public_key = self.tpm_key * G0
        self.tpm_policy = create_tpm_policy()
        logger.debug(f"Edge {self.id}: TPM key={self.tpm_key}, Public key={self.public_key}, Policy={self.tpm_policy}")