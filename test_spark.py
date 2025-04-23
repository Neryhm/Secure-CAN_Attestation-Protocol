import unittest
import logging
from charm.toolbox.pairinggroup import G1, G2, GT, ZR, pair
from src.config import PAIRING_GROUP, EDGES, IOT_DEVICES
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase
from src.crypto.ecc import verify_schnorr_proof, H, H1

logger = logging.getLogger(__name__)

class TestSPARKProtocol(unittest.TestCase):
    def setUp(self):
        """Initialize Key Setup and Join Phases."""
        logger.info("Setting up test environment")
        self.key_setup_result = key_setup_phase(EDGES, IOT_DEVICES, None, None, None, None)
        self.join_result = join_phase(self.key_setup_result)
        logger.info("Test setup completed")

    def test_curve(self):
        """Verify BN254 curve is used."""
        logger.info("Testing curve configuration")
        self.assertEqual(PAIRING_GROUP.curve, 'BN254', "Curve is not BN254")
        logger.debug("Curve verified: BN254")

    def test_group_elements(self):
        """Verify group elements belong to correct BN254 groups."""
        logger.info("Testing group elements")
        ks = self.key_setup_result
        self.assertTrue(ks['E'] == G1, "E is not G1")
        self.assertTrue(ks['E_tilde'] == G2, "E_tilde is not G2")
        self.assertTrue(ks['F_tilde'] == GT, "F_tilde is not GT")
        self.assertTrue(ks['G0'] in G1, "G0 not in G1")
        self.assertTrue(ks['G0_tilde'] in G2, "G0_tilde not in G2")
        self.assertTrue(all(gk in G1 for gk in ks['G_k']), "G_k elements not in G1")
        self.assertTrue(all(gkt in G2 for gkt in ks['G_k_tilde']), "G_k_tilde elements not in G2")
        self.assertTrue(ks['G'] in G1, "G not in G1")
        self.assertTrue(ks['G_tilde'] in G2, "G_tilde not in G2")
        logger.debug(f"Group elements verified: E={ks['E']}, E_tilde={ks['E_tilde']}, F_tilde={ks['F_tilde']}")

    def test_schnorr_proofs(self):
        """Verify Schnorr proofs for all public keys."""
        logger.info("Testing Schnorr proofs")
        ks = self.key_setup_result
        issuer = ks['issuer']
        tracer = ks['tracer']
        iots = ks['iots']

        # Issuer proofs
        self.assertTrue(verify_schnorr_proof(issuer.public_key['X_tilde'], ks['G_tilde'], issuer.proofs['X_tilde']),
                        "Issuer X_tilde proof invalid")
        self.assertTrue(verify_schnorr_proof(issuer.public_key['Y_tilde'], ks['G_tilde'], issuer.proofs['Y_tilde']),
                        "Issuer Y_tilde proof invalid")
        logger.debug("Issuer Schnorr proofs verified")

        # Tracer proof
        self.assertTrue(verify_schnorr_proof(tracer.public_key, ks['G'], tracer.proof),
                        "Tracer proof invalid")
        logger.debug("Tracer Schnorr proof verified")

        # IoT proofs
        for iot_id, iot in iots.items():
            k_index = int(iot_id.split('_D_')[-1]) - 1
            self.assertTrue(verify_schnorr_proof(iot.public_key, ks['G_k'][k_index], iot.proof),
                            f"IoT {iot_id} proof invalid")
        logger.debug("IoT Schnorr proofs verified")

    def test_cl_signatures(self):
        """Verify CL signatures for Edge and IoT credentials."""
        logger.info("Testing CL signatures")
        ks = self.key_setup_result
        jr = self.join_result
        issuer = ks['issuer']
        x = issuer.private_key['x']
        G = ks['G']
        edges = jr['edges']
        iots = jr['iots']

        for edge in edges:
            cre = edge.credential
            A, e, s = cre['A'], cre['e'], cre['s']
            B = edge.branch_key
            PK = edge.public_key
            # Verify: e(A, e(G_tilde, x) * G_tilde) == e(G + PK + H1(B)^s, G_tilde)
            left = pair(A, pair(G, issuer.public_key['X_tilde']) + ks['G_tilde'])
            right = pair(G + PK + H1(str(B)) * s, ks['G_tilde'])
            self.assertTrue(left == right, f"Edge {edge.id} CL signature invalid")
            logger.debug(f"Edge {edge.id} CL signature verified: A={A}, e={e}, s={s}")

        for iot_id, iot in iots.items():
            cre = iot.credential
            A, e, s = cre['A'], cre['e'], cre['s']
            B = [edge.branch_key for edge in edges if iot_id.startswith(edge.id)][0]
            X_k = iot.public_key
            left = pair(A, pair(G, issuer.public_key['X_tilde']) + ks['G_tilde'])
            right = pair(G + X_k + H1(str(B)) * s, ks['G_tilde'])
            self.assertTrue(left == right, f"IoT {iot_id} CL signature invalid")
            logger.debug(f"IoT {iot_id} CL signature verified: A={A}, e={e}, s={s}")

    def test_elgamal_tokens(self):
        """Verify ElGamal tracing tokens by decryption."""
        logger.info("Testing ElGamal tracing tokens")
        ks = self.key_setup_result
        jr = self.join_result
        tracer = jr['tracer']
        iots = jr['iots']
        x_T = tracer.private_key

        for iot_id, iot in iots.items():
            token = iot.tracing_token
            C1, C2 = token['C1'], token['C2']
            # Decrypt: X_k = C2 - x_T * C1
            decrypted_X_k = C2 - x_T * C1
            self.assertTrue(decrypted_X_k == iot.public_key, f"IoT {iot_id} tracing token invalid")
            logger.debug(f"IoT {iot_id} tracing token verified: C1={C1}, C2={C2}, Decrypted={decrypted_X_k}")

    def test_tpm_signatures(self):
        """Verify simulated TPM signatures."""
        logger.info("Testing TPM signatures")
        jr = self.join_result
        edges = jr['edges']
        G = self.key_setup_result['G']

        for edge in edges:
            # TPM signature is a Schnorr proof on PK
            self.assertTrue(verify_schnorr_proof(edge.public_key, G, edge.credential['tpm_signature']),
                            f"Edge {edge.id} TPM signature invalid")
            logger.debug(f"Edge {edge.id} TPM signature verified")

    def test_variables(self):
        """Ensure all variables from Sections 7.1 and 7.2 are present."""
        logger.info("Testing presence of all variables")
        ks = self.key_setup_result
        jr = self.join_result

        # Section 7.1 variables
        expected_ks_vars = ['E', 'E_tilde', 'F_tilde', 'G0', 'G0_tilde', 'G_k', 'G_k_tilde', 'r_k',
                            'G', 'G_tilde', 'r_G', 'issuer', 'tracer', 'v_int', 'v_ext', 'edges', 'iots']
        for var in expected_ks_vars:
            self.assertIn(var, ks, f"Key Setup variable {var} missing")
        logger.debug("Key Setup variables verified")

        # Section 7.2 variables (per Edge/IoT)
        for edge in jr['edges']:
            self.assertIsNotNone(edge.tpm_key, f"Edge {edge.id} missing tpm_key")
            self.assertIsNotNone(edge.public_key, f"Edge {edge.id} missing public_key")
            self.assertIsNotNone(edge.tpm_policy, f"Edge {edge.id} missing tpm_policy")
            self.assertIsNotNone(edge.branch_key, f"Edge {edge.id} missing branch_key")
            self.assertIsNotNone(edge.credential, f"Edge {edge.id} missing credential")
            logger.debug(f"Edge {edge.id} variables verified")

        for iot_id, iot in jr['iots'].items():
            self.assertIsNotNone(iot.private_key, f"IoT {iot_id} missing private_key")
            self.assertIsNotNone(iot.public_key, f"IoT {iot_id} missing public_key")
            self.assertIsNotNone(iot.credential, f"IoT {iot_id} missing credential")
            self.assertIsNotNone(iot.tracing_token, f"IoT {iot_id} missing tracing_token")
            logger.debug(f"IoT {iot_id} variables verified")

if __name__ == '__main__':
    with open('test_spark.txt', 'w') as f:
        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        unittest.main(testRunner=runner)