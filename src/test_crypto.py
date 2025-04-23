import unittest
import logging
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
from config import GROUP, G0, G0_tilde, BASENAME, EDGE_IOT_COUNTS
from crypto_utils import CryptoUtils
from tpm_simulator import TPMSimulator
from entities import IoTDevice, EdgeDevice, Issuer, Verifier, Tracer
from protocol import SPARKProtocol

# Configure logging for test_crypto.py
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spark_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
# Set console handler to ERROR to minimize terminal output
for handler in logger.handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.setLevel(logging.ERROR)

class TestSPARKProtocol(unittest.TestCase):
    def setUp(self):
        """Initialize test environment."""
        self.protocol = SPARKProtocol()
        self.message = b"Test message"
        self.edge = self.protocol.edges[0]  # Edge 1 with 3 IoT devices
        self.issuer_keys = self.protocol.issuer.public_key
        logger.info("Test setup completed for Edge %d", self.edge.id)

    def test_schnorr_signature(self):
        """Test EC-Schnorr signature."""
        private_key = GROUP.random(ZR)
        public_key = private_key * G0
        k = GROUP.random(ZR)
        signature = CryptoUtils.generate_schnorr_signature(private_key, self.message, k)
        result = CryptoUtils.verify_schnorr_signature(public_key, self.message, signature)
        logger.info("Schnorr signature test: %s", result)
        self.assertTrue(result)

    def test_cl_credential(self):
        """Test CL credential generation and verification."""
        branch_key = self.edge.tpm.public_key
        cred = CryptoUtils.generate_cl_credential(
            {'private': self.protocol.issuer.private_key, 'public': self.issuer_keys},
            branch_key,
            self.edge.num_iot
        )
        result = CryptoUtils.verify_cl_credential(cred, self.issuer_keys, branch_key)
        logger.info("CL credential test: %s", result)
        self.assertTrue(result)

    def test_elgamal_encryption(self):
        """Test ElGamal encryption and decryption."""
        private_key = GROUP.random(ZR)
        public_key = private_key * G0
        message = GROUP.random(ZR)
        ciphertext = CryptoUtils.elgamal_encrypt(public_key, message)
        decrypted = CryptoUtils.elgamal_decrypt(private_key, ciphertext)
        logger.info("ElGamal test: decrypted=%s", decrypted)
        self.assertEqual(decrypted, message * G0)

    def test_zkp(self):
        """Test zero-knowledge proof."""
        secret = GROUP.random(ZR)
        public_key = secret * G0
        r, commitment = CryptoUtils.generate_zkp_commitment(secret)
        challenge = CryptoUtils.hash_to_Zq(b"test")
        response = CryptoUtils.generate_zkp_response(secret, r, challenge)
        result = CryptoUtils.verify_zkp(public_key, commitment, challenge, response)
        logger.info("ZKP test: %s", result)
        self.assertTrue(result)

    def test_key_setup_phase(self):
        """Test Key Setup Phase."""
        self.protocol.key_setup_phase()
        for edge in self.protocol.edges:
            self.assertIsNotNone(edge.tpm.public_key)
            for iot in edge.iot_devices:
                self.assertIsNotNone(iot.public_key)
        logger.info("Key Setup Phase test: Passed")

    def test_join_phase(self):
        """Test Join Phase."""
        self.protocol.join_phase()
        for edge in self.protocol.edges:
            self.assertIsNotNone(edge.credential)
            self.assertIsNotNone(edge.tpm.trace_key)
            self.assertIn(edge.tpm.trace_key, self.protocol.tracer.records)
        logger.info("Join Phase test: Passed")

    def test_attestation_phase(self):
        """Test Attestation Phase."""
        self.protocol.join_phase()
        signature = self.protocol.attestation_phase(self.edge, self.message)
        self.assertIn('A_prime', signature)
        self.assertIn('ENC(TK)', signature)
        logger.info("Attestation Phase test: Signature generated")

    def test_verification_phase(self):
        """Test Verification Phase."""
        self.protocol.join_phase()
        signature = self.protocol.attestation_phase(self.edge, self.message)
        result = self.protocol.verification_phase(signature, self.message, self.edge)
        logger.info("Verification Phase test: %s", result)
        self.assertTrue(result)

    def test_tracing_phase(self):
        """Test Tracing Phase."""
        self.protocol.join_phase()
        signature = self.protocol.attestation_phase(self.edge, self.message)
        traced_pk = self.protocol.tracing_phase(signature)
        logger.info("Tracing Phase test: traced_pk=%s", traced_pk)
        self.assertEqual(traced_pk, self.edge.tpm.public_key)

if __name__ == '__main__':
    unittest.main()