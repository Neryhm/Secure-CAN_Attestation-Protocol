import unittest
import logging
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair
from src.config import PAIRING_GROUP, EDGES, IOT_DEVICES
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase
from src.protocols.attestation import attest_device
from src.protocols.verification import verify_signature
from src.network.can_sim import simulate_can_bus
from src.crypto.ecc import H, verify_schnorr_proof
from src.entities.issuer import Issuer
from src.entities.tracer import Tracer
from src.entities.verifier import Verifier

logger = logging.getLogger(__name__)

class TestSPARKProtocol(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.issuer = Issuer()
        self.tracer = Tracer()
        self.v_int = Verifier("V_int")
        self.v_ext = Verifier("V_ext")
        try:
            self.key_setup_result = key_setup_phase(
                EDGES, IOT_DEVICES, self.issuer, self.tracer, self.v_int, self.v_ext
            )
            self.join_result = join_phase(self.key_setup_result)
            self.edges = self.join_result['edges']
            self.iots = self.join_result['iots']
            self.G = self.key_setup_result['G']
            self.G_tilde = self.key_setup_result['G_tilde']
            self.G0 = self.key_setup_result['G0']
            self.G_k = self.key_setup_result['G_k']
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            raise

    def test_curve(self):
        """Verify BN254 curve."""
        order = PAIRING_GROUP.order()
        expected_order = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        self.assertEqual(order, expected_order, "Curve order does not match BN254")

    def test_group_elements(self):
        """Verify group elements in BN254 groups."""
        ks = self.key_setup_result
        self.assertTrue(PAIRING_GROUP.ismember(ks['G0'], G1), "G0 not in G1")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G0_tilde'], G2), "G0_tilde not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G'], G1), "G not in G1")
        self.assertTrue(PAIRING_GROUP.ismember(ks['G_tilde'], G2), "G_tilde not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(self.issuer.public_key['X_tilde'], G2), "X_tilde not in G2")
        self.assertTrue(PAIRING_GROUP.ismember(self.issuer.public_key['Y_tilde'], G2), "Y_tilde not in G2")
        for edge in self.edges:
            self.assertTrue(PAIRING_GROUP.ismember(edge.public_key, G1), f"Edge {edge.id} PK not in G1")
        for iot in self.iots.values():
            self.assertTrue(PAIRING_GROUP.ismember(iot.public_key, G1), f"IoT {iot.id} PK not in G1")

    def test_schnorr_proofs(self):
        """Verify Schnorr proofs."""
        for edge in self.edges:
            proof = edge.credential['tpm_signature']
            self.assertTrue(verify_schnorr_proof(edge.public_key, self.G, proof),
                          f"Edge {edge.id} Schnorr proof invalid")
        for iot in self.iots.values():
            k_index = int(iot.id.split('_D_')[-1]) - 1
            self.assertTrue(verify_schnorr_proof(iot.public_key, self.G_k[k_index], iot.proof),
                          f"IoT {iot.id} Schnorr proof invalid")
        self.assertTrue(verify_schnorr_proof(self.issuer.public_key['X_tilde'], self.G_tilde, self.issuer.proofs['X_tilde']),
                      "Issuer X_tilde Schnorr proof invalid")
        self.assertTrue(verify_schnorr_proof(self.issuer.public_key['Y_tilde'], self.G_tilde, self.issuer.proofs['Y_tilde']),
                      "Issuer Y_tilde Schnorr proof invalid")
        self.assertTrue(verify_schnorr_proof(self.tracer.public_key, self.G, self.tracer.proof),
                      "Tracer Schnorr proof invalid")

    def test_cl_signatures(self):
        """Verify CL signatures for credentials."""
        issuer_x = self.issuer.private_key['x']
        issuer_y = self.issuer.private_key['y']
        for edge in self.edges:
            cred = edge.credential
            A, B, C, D, E0, E_k, challenge = (
                cred['A'], cred['B'], cred['C'], cred['D'], cred['E0'], cred['E_k'], cred['challenge']
            )
            self.assertTrue(PAIRING_GROUP.ismember(A, G1), f"Edge {edge.id} A not in G1")
            self.assertEqual(pair(B, self.G_tilde), pair(A, self.issuer.public_key['Y_tilde']),
                           f"Edge {edge.id} B invalid")
            expected_C = pair(C, self.G_tilde)
            computed_C = pair(A, self.issuer.public_key['X_tilde']) * pair(edge.branch_key, self.issuer.public_key['X_tilde'] * issuer_y)
            self.assertEqual(expected_C, computed_C, f"Edge {edge.id} C invalid")
            expected_challenge = H(str(A) + ''.join(str(self.G_k[i]) for i in range(len(edge.iots))) + str(edge.branch_key))
            self.assertEqual(challenge, expected_challenge, f"Edge {edge.id} challenge invalid")
        for iot in self.iots.values():
            cred = iot.credential
            A, B, C, D, E0, E_k, challenge = (
                cred['A'], cred['B'], cred['C'], cred['D'], cred['E0'], cred['E_k'], cred['challenge']
            )
            self.assertTrue(PAIRING_GROUP.ismember(A, G1), f"IoT {iot.id} A not in G1")
            self.assertEqual(pair(B, self.G_tilde), pair(A, self.issuer.public_key['Y_tilde']),
                           f"IoT {iot.id} B invalid")
            edge_id = iot.id.split('_D_')[0]
            edge = next(e for e in self.edges if e.id == edge_id)
            expected_C = pair(C, self.G_tilde)
            computed_C = pair(A, self.issuer.public_key['X_tilde']) * pair(edge.branch_key, self.issuer.public_key['X_tilde'] * issuer_y)
            self.assertEqual(expected_C, computed_C, f"IoT {iot.id} C invalid")
            expected_challenge = H(str(A) + ''.join(str(self.G_k[i]) for i in range(len(edge.iots))) + str(edge.branch_key))
            self.assertEqual(challenge, expected_challenge, f"IoT {iot.id} challenge invalid")

    def test_elgamal_tokens(self):
        """Verify ElGamal tracing tokens."""
        tracer_sk = self.tracer.private_key
        for iot in self.iots.values():
            C1, C2 = iot.tracing_token['C1'], iot.tracing_token['C2']
            self.assertTrue(PAIRING_GROUP.ismember(C1, G1), f"IoT {iot.id} C1 not in G1")
            self.assertTrue(PAIRING_GROUP.ismember(C2, G1), f"IoT {iot.id} C2 not in G1")
            decrypted = C2 - tracer_sk * C1
            self.assertEqual(decrypted, iot.public_key, f"IoT {iot.id} ElGamal token invalid")

    def test_tpm_signatures(self):
        """Verify TPM signatures."""
        for edge in self.edges:
            proof = edge.credential['tpm_signature']
            self.assertTrue(verify_schnorr_proof(edge.public_key, self.G, proof),
                          f"Edge {edge.id} TPM signature invalid")

    def test_variables(self):
        """Verify variables from Sections 7.1 and 7.2."""
        ks = self.key_setup_result
        self.assertIn('E', ks, "E missing")
        self.assertIn('E_tilde', ks, "E_tilde missing")
        self.assertIn('F_tilde', ks, "F_tilde missing")
        self.assertIn('G0', ks, "G0 missing")
        self.assertIn('G0_tilde', ks, "G0_tilde missing")
        self.assertIn('G_k', ks, "G_k missing")
        self.assertIn('G_k_tilde', ks, "G_k_tilde missing")
        self.assertIn('G', ks, "G missing")
        self.assertIn('G_tilde', ks, "G_tilde missing")
        self.assertIn('issuer', ks, "Issuer missing")
        self.assertIn('tracer', ks, "Tracer missing")
        for edge in self.edges:
            for key in ['public_key', 'tpm_key', 'tpm_policy', 'branch_key', 'credential']:
                self.assertTrue(hasattr(edge, key), f"Edge {edge.id} {key} missing")
            for key in ['A', 'B', 'C', 'D', 'E0', 'E_k', 'challenge']:
                self.assertIn(key, edge.credential, f"Edge {edge.id} {key} missing")
        for iot in self.iots.values():
            for key in ['public_key', 'private_key', 'credential', 'tracing_token']:
                self.assertTrue(hasattr(iot, key), f"IoT {iot.id} {key} missing")
            for key in ['A', 'B', 'C', 'D', 'E0', 'E_k', 'challenge']:
                self.assertIn(key, iot.credential, f"IoT {iot.id} {key} missing")
            for key in ['C1', 'C2']:
                self.assertIn(key, iot.tracing_token, f"IoT {iot.id} {key} missing")

    def test_attestation(self):
        """Verify DAA-A group signature generation."""
        message = "Test attestation"
        for edge in self.edges:
            signature = attest_device(edge, self.key_setup_result, self.join_result, message)
            for key in ['T1', 'T2', 'T3', 'T4', 'T5', 'c', 's1', 's2', 's3']:
                self.assertIn(key, signature, f"Edge {edge.id} signature {key} missing")
            for key in ['T1', 'T2', 'T3', 'T4']:
                self.assertTrue(PAIRING_GROUP.ismember(signature[key], G1), f"Edge {edge.id} {key} not in G1")
            for T5_i in signature['T5']:
                self.assertTrue(PAIRING_GROUP.ismember(T5_i, G1), f"Edge {edge.id} T5_i not in G1")
        for iot in self.iots.values():
            signature = attest_device(iot, self.key_setup_result, self.join_result, message)
            for key in ['T1', 'T2', 'T3', 'T4', 'T5', 'c', 's1', 's2', 's3']:
                self.assertIn(key, signature, f"IoT {iot.id} signature {key} missing")
            for key in ['T1', 'T2', 'T3', 'T4']:
                self.assertTrue(PAIRING_GROUP.ismember(signature[key], G1), f"IoT {iot.id} {key} not in G1")
            for T5_i in signature['T5']:
                self.assertTrue(PAIRING_GROUP.ismember(T5_i, G1), f"IoT {iot.id} T5_i not in G1")

    def test_verification(self):
        """Verify DAA-A group signatures."""
        message = "Test attestation"
        for edge in self.edges:
            signature = attest_device(edge, self.key_setup_result, self.join_result, message)
            self.assertTrue(
                verify_signature(signature, self.key_setup_result, self.join_result, edge,
                               message=message, device_policy=edge.tpm_policy),
                f"Edge {edge.id} signature verification failed"
            )
        for iot in self.iots.values():
            signature = attest_device(iot, self.key_setup_result, self.join_result, message)
            self.assertTrue(
                verify_signature(signature, self.key_setup_result, self.join_result, iot,
                               message=message, device_policy=None),
                f"IoT {iot.id} signature verification failed"
            )

    def test_can_simulation(self):
        """Verify CAN bus simulation."""
        messages = simulate_can_bus(self.key_setup_result, self.join_result)
        self.assertEqual(len(messages), len(self.edges), f"Expected {len(self.edges)} messages")
        for message in messages:
            sender_id = message['sender_id']
            payload = message['payload']
            signature = message['signature']
            edge = next((e for e in self.edges if e.id == sender_id), None)
            self.assertIsNotNone(edge, f"Edge {sender_id} not found")
            expected_iot_count = len([iot for iot in self.iots.values() if iot.id.startswith(sender_id)])
            self.assertEqual(len(payload), expected_iot_count, f"Edge {sender_id} payload size mismatch")
            self.assertTrue(
                verify_signature(signature, self.key_setup_result, self.join_result, edge,
                               message="CAN message", device_policy=edge.tpm_policy),
                f"Edge {sender_id} message signature verification failed"
            )

    def test_revocation(self):
        """Verify revoked Edge fails join."""
        edge = self.edges[0]
        self.issuer.revocation_list.add(edge.public_key)
        with self.assertRaises(ValueError, msg=f"Edge {edge.id} should fail join"):
            join_phase(self.key_setup_result)

if __name__ == '__main__':
    unittest.main()