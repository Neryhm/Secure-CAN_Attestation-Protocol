import unittest
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR
from src.config import PAIRING_GROUP
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase
from src.protocols.attestation import attest_device
from src.protocols.verification import verify_signature
from src.network.can_sim import simulate_can_bus
from src.crypto.ecc import H, verify_schnorr_proof

class TestSPARKProtocol(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.key_setup_result = key_setup_phase()
        self.join_result = join_phase(self.key_setup_result)
        self.edges = self.join_result['edges']
        self.iots = self.join_result['iots']
        self.issuer = self.join_result['issuer']
        self.tracer = self.join_result['tracer']
        self.G = self.key_setup_result['G']
        self.G_tilde = self.key_setup_result['G_tilde']

    def test_curve(self):
        """Verify BN254 curve is used."""
        order = PAIRING_GROUP.order()
        expected_order = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        self.assertEqual(order, expected_order, "Curve order does not match BN254")

    def test_group_elements(self):
        """Verify group elements belong to correct BN254 groups."""
        ks = self.key_setup_result
        self.assertTrue(PAIRING_GROUP.ismember(ks['G0'], G1), "G0 not in G1")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G0_tilde'][0], G2), "G0_tilde[0] not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G0_tilde'][1], G2), "G0_tilde[1] not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G'], G1), "G not in G1")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G_tilde'][0], G2), "G_tilde[0] not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G_tilde'][1], G2), "G_tilde[1] not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(self.issuer.public_key['X_tilde'][0], G2), "X_tilde[0] not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(self.issuer.public_key['Y_tilde'][0], G2), "Y_tilde[0] not in G2")
        for edge in self.edges:
            self.assertTrue(PAIRING_GROUP.ismember(edge.public_key, G1), f"Edge {edge.id} PK not in G1")
        for iot in self.iots.values():
            self.assertTrue(PAIRING_GROUP.ismember(iot.public_key, G1), f"IoT {iot.id} PK not in G1")

    def test_schnorr_proofs(self):
        """Verify Schnorr proofs for all public keys."""
        for edge in self.edges:
            proof = edge.credential['tpm_signature']
            self.assertTrue(verify_schnorr_proof(edge.public_key, self.G, proof),
                          f"Edge {edge.id} Schnorr proof invalid")
        for iot in self.iots.values():
            self.assertTrue(verify_schnorr_proof(iot.public_key, self.G, iot.proof),
                          f"IoT {iot.id} Schnorr proof invalid")
        issuer_proofs = self.issuer.public_key['proofs']
        for key in ['X_tilde', 'Y_tilde']:
            proof = issuer_proofs[key]
            self.assertTrue(verify_schnorr_proof(self.issuer.public_key[key][0], self.G_tilde[0], proof),
                          f"Issuer {key} Schnorr proof invalid")
        self.assertTrue(verify_schnorr_proof(self.tracer.public_key, self.G, self.tracer.proof),
                      "Tracer Schnorr proof invalid")

    def test_cl_signatures(self):
        """Verify CL signatures for Edge and IoT credentials."""
        issuer_x = self.issuer.private_key['x']
        for edge in self.edges:
            A, e, s = edge.credential['A'], edge.credential['e'], edge.credential['s']
            self.assertTrue(PAIRING_GROUP.ismember(A, G1), f"Edge {edge.id} A not in G1")
            H1_B = edge.credential.get('H1_B', None)
            if H1_B is None:
                H1_B = H(str(edge.branch_key))
            expected = A ** (e + issuer_x)
            computed = self.G + edge.public_key + H1_B * s
            self.assertEqual(expected, computed, f"Edge {edge.id} CL signature invalid")
        for iot in self.iots.values():
            A, e, s = iot.credential['A'], iot.credential['e'], iot.credential['s']
            self.assertTrue(PAIRING_GROUP.ismember(A, G1), f"IoT {iot.id} A not in G1")
            edge_id = iot.id.split('_D_')[0]
            edge = next((e for e in self.edges if e.id == edge_id), None)
            H1_B = edge.credential.get('H1_B', None)
            if H1_B is None:
                H1_B = H(str(edge.branch_key))
            expected = A ** (e + issuer_x)
            computed = self.G + iot.public_key + H1_B * s
            self.assertEqual(expected, computed, f"IoT {iot.id} CL signature invalid")

    def test_elgamal_tokens(self):
        """Verify ElGamal tracing tokens by decryption."""
        tracer_sk = self.tracer.private_key
        for iot in self.iots.values():
            C1, C2 = iot.tracing_token['C1'], iot.tracing_token['C2']
            self.assertTrue(PAIRING_GROUP.ismember(C1, G1), f"IoT {iot.id} C1 not in G1")
            self.assertTrue(PAIRING_GROUP.ismember(C2, G1), f"IoT {iot.id} C2 not in G1")
            decrypted = C2 - tracer_sk * C1
            self.assertEqual(decrypted, iot.public_key, f"IoT {iot.id} ElGamal token invalid")

    def test_tpm_signatures(self):
        """Verify simulated TPM signatures."""
        for edge in self.edges:
            proof = edge.credential['tpm_signature']
            c = proof['c']
            sigma = proof['sigma']
            R = proof['R']
            computed_c = H((self.G, edge.public_key, R))
            self.assertEqual(c, computed_c, f"Edge {edge.id} TPM signature hash invalid")
            self.assertTrue(PAIRING_GROUP.ismember(R, G1), f"Edge {edge.id} R not in G1")
            expected = sigma * self.G
            computed = c * edge.public_key + R
            self.assertEqual(expected, computed, f"Edge {edge.id} TPM signature invalid")

    def test_variables(self):
        """Ensure all variables from Sections 7.1 and 7.2 are present."""
        ks = self.key_setup_result
        self.assertIn('E', ks, "E missing")
        self.assertIn('E_tilde', ks, "E_tilde missing")
        self.assertIn('F_tilde', ks, "F_tilde missing")
        self.assertIn('G0', ks, "G0 missing")
        self.assertIn('G0_tilde', ks, "G0_tilde missing")
        self.assertIn('r_k', ks, "r_k missing")
        self.assertIn('G_k', ks, "G_k missing")
        self.assertIn('G_k_tilde', ks, "G_k_tilde missing")
        self.assertIn('r_G', ks, "r_G missing")
        self.assertIn('G', ks, "G missing")
        self.assertIn('G_tilde', ks, "G_tilde missing")
        self.assertIn('issuer', ks, "Issuer missing")
        self.assertIn('tracer', ks, "Tracer missing")
        self.assertIn('x', ks['issuer'].private_key, "Issuer x missing")
        self.assertIn('y', ks['issuer'].private_key, "Issuer y missing")
        self.assertIn('X_tilde', ks['issuer'].public_key, "Issuer X_tilde missing")
        self.assertIn('Y_tilde', ks['issuer'].public_key, "Issuer Y_tilde missing")
        self.assertIn('x_T', ks['tracer'].private_key, "Tracer x_T missing")
        self.assertIn('X_T', ks['tracer'].public_key, "Tracer X_T missing")
        for edge in self.edges:
            self.assertTrue(hasattr(edge, 'public_key'), f"Edge {edge.id} PK missing")
            self.assertTrue(hasattr(edge, 'tpm_key'), f"Edge {edge.id} TPM key missing")
            self.assertTrue(hasattr(edge, 'tpm_policy'), f"Edge {edge.id} TPM policy missing")
            self.assertTrue(hasattr(edge, 'branch_key'), f"Edge {edge.id} branch key missing")
            self.assertTrue(hasattr(edge, 'credential'), f"Edge {edge.id} credential missing")
            self.assertIn('A', edge.credential, f"Edge {edge.id} A missing")
            self.assertIn('e', edge.credential, f"Edge {edge.id} e missing")
            self.assertIn('s', edge.credential, f"Edge {edge.id} s missing")
            self.assertIn('tpm_signature', edge.credential, f"Edge {edge.id} TPM signature missing")
        for iot in self.iots.values():
            self.assertTrue(hasattr(iot, 'public_key'), f"IoT {iot.id} PK missing")
            self.assertTrue(hasattr(iot, 'private_key'), f"IoT {iot.id} private key missing")
            self.assertTrue(hasattr(iot, 'credential'), f"IoT {iot.id} credential missing")
            self.assertIn('A', iot.credential, f"IoT {iot.id} A missing")
            self.assertIn('e', iot.credential, f"IoT {iot.id} e missing")
            self.assertIn('s', iot.credential, f"IoT {iot.id} s missing")
            self.assertTrue(hasattr(iot, 'tracing_token'), f"IoT {iot.id} tracing token missing")
            self.assertIn('C1', iot.tracing_token, f"IoT {iot.id} C1 missing")
            self.assertIn('C2', iot.tracing_token, f"IoT {iot.id} C2 missing")

    def test_attestation(self):
        """Verify DAA-A group signature generation."""
        for edge in self.edges:
            signature = attest_device(edge, self.key_setup_result, self.join_result)
            self.assertIn('T1', signature, f"Edge {edge.id} signature T1 missing")
            self.assertIn('T2', signature, f"Edge {edge.id} signature T2 missing")
            self.assertIn('c', signature, f"Edge {edge.id} signature c missing")
            self.assertIn('s1', signature, f"Edge {edge.id} signature s1 missing")
            self.assertIn('s2', signature, f"Edge {edge.id} signature s2 missing")
            self.assertTrue(PAIRING_GROUP.ismember(signature['T1'], G1), f"Edge {edge.id} T1 not in G1")
            self.assertTrue(PAIRING_GROUP.ismember(signature['T2'], G1), f"Edge {edge.id} T2 not in G1")
        for iot in self.iots.values():
            signature = attest_device(iot, self.key_setup_result, self.join_result)
            self.assertIn('T1', signature, f"IoT {iot.id} signature T1 missing")
            self.assertIn('T2', signature, f"IoT {iot.id} signature T2 missing")
            self.assertIn('c', signature, f"IoT {iot.id} signature c missing")
            self.assertIn('s1', signature, f"IoT {iot.id} signature s1 missing")
            self.assertIn('s2', signature, f"IoT {iot.id} signature s2 missing")
            self.assertTrue(PAIRING_GROUP.ismember(signature['T1'], G1), f"IoT {iot.id} T1 not in G1")
            self.assertTrue(PAIRING_GROUP.ismember(signature['T2'], G1), f"IoT {iot.id} T2 not in G1")

    def test_verification(self):
        """Verify DAA-A group signatures."""
        for edge in self.edges:
            signature = attest_device(edge, self.key_setup_result, self.join_result)
            self.assertTrue(verify_signature(signature, self.key_setup_result, self.join_result, edge.tpm_policy),
                           f"Edge {edge.id} signature verification failed")
        for iot in self.iots.values():
            signature = attest_device(iot, self.key_setup_result, self.join_result)
            self.assertTrue(verify_signature(signature, self.key_setup_result, self.join_result),
                           f"IoT {iot.id} signature verification failed")

    def test_can_simulation(self):
        """Verify CAN bus simulation with attested messages."""
        messages = simulate_can_bus(self.key_setup_result, self.join_result)
        self.assertEqual(len(messages), 4, "Expected 4 messages from 4 Edges")
        for message in messages:
            sender_id = message['sender_id']
            payload = message['payload']
            signature = message['signature']
            edge = next((e for e in self.edges if e.id == sender_id), None)
            self.assertIsNotNone(edge, f"Edge {sender_id} not found")
            expected_iot_count = len([iot for iot in self.iots.values() if iot.id.startswith(sender_id)])
            self.assertEqual(len(payload), expected_iot_count, f"Edge {sender_id} payload size mismatch")
            self.assertTrue(verify_signature(signature, self.key_setup_result, self.join_result, edge.tpm_policy),
                           f"Edge {sender_id} message signature verification failed")

if __name__ == '__main__':
    unittest.main()