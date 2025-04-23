import unittest
import logging
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2
from config import GROUP, G0, G0_tilde
from crypto_utils import CryptoUtils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestCryptoUtils(unittest.TestCase):
    def setUp(self):
        self.message = b"Test message"
        self.private_key = GROUP.random(ZR)
        self.public_key = self.private_key * G0
        self.issuer_keys = {
            'private': {'x': GROUP.random(ZR), 'y': GROUP.random(ZR)},
            'public': {
                'X': GROUP.random(ZR) * G0_tilde,
                'Y': GROUP.random(ZR) * G0_tilde
            }
        }

    def test_schnorr_signature(self):
        """Test EC-Schnorr signature generation and verification."""
        k = GROUP.random(ZR)
        signature = CryptoUtils.generate_schnorr_signature(self.private_key, self.message, k)
        result = CryptoUtils.verify_schnorr_signature(self.public_key, self.message, signature)
        logger.info("Schnorr signature test: %s", result)
        self.assertTrue(result)

    def test_cl_credential(self):
        """Test CL credential generation and basic verification."""
        branch_key = self.public_key
        num_iot = 3
        cred = CryptoUtils.generate_cl_credential(self.issuer_keys, branch_key, num_iot)
        self.assertIn('A', cred)
        self.assertIn('B', cred)
        self.assertIn('C', cred)
        self.assertIn('D', cred)
        self.assertIn('E0', cred)
        self.assertEqual(len(cred['E_k']), num_iot)
        logger.info("CL credential test: Generated credential with %d E_k elements", num_iot)

    def test_elgamal_encryption(self):
        """Test ElGamal encryption and decryption."""
        message = GROUP.random(ZR)
        ciphertext = CryptoUtils.elgamal_encrypt(self.public_key, message)
        decrypted = CryptoUtils.elgamal_decrypt(self.private_key, ciphertext)
        self.assertEqual(decrypted, message * G0)
        logger.info("ElGamal encryption test: Successful")

    def test_pairing(self):
        """Test Type III pairing computation."""
        a = GROUP.random(G1)
        b = GROUP.random(G2)
        result = CryptoUtils.compute_pairing(a, b)
        self.assertIsNotNone(result)
        logger.info("Pairing test: Successful")

if __name__ == '__main__':
    unittest.main()