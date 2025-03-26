import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import unittest
import asyncio
from unittest import IsolatedAsyncioTestCase
from src.crypto.primitives import CryptoPrimitives
from src.entities.tpm_emulator import TPMEmulator
from src.entities.devices import Issuer, EdgeDevice, IoTDevice, InternalVerifier, Tracer
from src.phases.key_setup import KeySetup
from src.phases.join import JoinPhase
from src.phases.attestation import AttestationPhase
from src.phases.verification import VerificationPhase
from src.network.comms import NetworkSimulator

class TestSparkSimulation(IsolatedAsyncioTestCase):
    """Unit tests for the SPARK protocol simulation."""

    def setUp(self):
        """Setup common test fixtures."""
        self.crypto = CryptoPrimitives()
        self.group_elements = {
            'G_0': self.crypto.g1,
            'G_1': self.crypto.group.random(),
            'G_2': self.crypto.group.random(),
            'H_0': self.crypto.group.random(),
            'H_1': self.crypto.group.random(),
            'G_0_bar': self.crypto.g2
        }
        self.issuer = Issuer()
        self.verifier = InternalVerifier()
        self.edge = EdgeDevice("edge_1")
        self.iot1 = IoTDevice("iot_1")
        self.iot2 = IoTDevice("iot_2")
        self.tracer = Tracer(self.issuer.tracing_keypair[0])
        self.edge_devices = [self.edge]
        self.iot_devices_per_edge = {"edge_1": [self.iot1, self.iot2]}

    def test_crypto_primitives(self):
        """Test cryptographic primitives."""
        # Test pairing
        a = self.crypto.generate_random_Zq()
        b = self.crypto.generate_random_Zq()
        self.assertEqual(
            self.crypto.pairing(self.crypto.ec_multiply(a, self.crypto.g1), self.crypto.g2),
            self.crypto.pairing(self.crypto.g1, self.crypto.ec_multiply(b, self.crypto.g2))
        )
        
        # Test Schnorr signature
        msg = "test"
        sig = self.crypto.schnorr_sign(a, msg, self.crypto.g1)
        pk = self.crypto.ec_multiply(a, self.crypto.g1)
        self.assertTrue(self.crypto.schnorr_verify(pk, msg, sig, self.crypto.g1))

    def test_tpm_emulator(self):
        """Test TPM emulator functionality."""
        tpm = TPMEmulator()
        tpm.initialize()
        tpm.extend_pcr(0, b"update")
        expected_pcrs = {0: tpm.pcrs[0]}
        tpm.set_policy(expected_pcrs)
        
        E_point = self.crypto.ec_multiply(self.crypto.generate_random_Zq(), self.crypto.g1)
        R, _ = tpm.TPM2_Commit(E_point)
        c = self.crypto.hash_to_Zq(R, "msg")
        s = tpm.TPM2_Sign(c)
        left = self.crypto.ec_multiply(s, E_point)
        right = self.crypto.ec_add(R, self.crypto.ec_multiply(c, tpm.public_key))
        self.assertEqual(left, right)

    def test_entities(self):
        """Test entity interactions."""
        self.issuer.generate_tracing_keypair()
        self.tracer = Tracer(self.issuer.tracing_keypair[0])
        self.edge.add_iot_device(self.iot1)
        self.assertIn(self.iot1.branch_key, self.edge.branch_keys.values())
        self.assertEqual(self.edge.public_key, self.edge.tpm.public_key)

    async def test_key_setup(self):
        """Test Key Setup phase."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        self.assertIn('G_2', group_elements)
        self.assertIsNotNone(self.iot1.public_key)

    async def test_join(self):
        """Test Join phase."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        join = JoinPhase(group_elements)
        join.run(self.issuer, self.edge_devices, self.iot_devices_per_edge)
        self.assertIsNotNone(self.edge.credential)
        self.assertIsNotNone(self.edge.tracing_token)

    async def test_attestation(self):
        """Test Attestation phase with network."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        join = JoinPhase(group_elements)
        join.run(self.issuer, self.edge_devices, self.iot_devices_per_edge)
        
        attestation = AttestationPhase(group_elements)
        signatures = await attestation.run(self.verifier, self.edge_devices)
        self.assertIn("edge_1", signatures)

    async def test_verification(self):
        """Test Verification phase."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        join = JoinPhase(group_elements)
        join.run(self.issuer, self.edge_devices, self.iot_devices_per_edge)
        attestation = AttestationPhase(group_elements)
        await attestation.run(self.verifier, self.edge_devices)
        
        verification = VerificationPhase(group_elements)
        results = await verification.run(self.verifier, self.edge_devices)
        self.assertTrue(results["edge_1"])

    async def test_tracing(self):
        """Test Tracing functionality."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        join = JoinPhase(group_elements)
        join.run(self.issuer, self.edge_devices, self.iot_devices_per_edge)
        
        traced_id = self.tracer.trace_device(self.edge)
        self.assertEqual(traced_id, "edge_1")
        
        # Edge case: Tracing with no token
        edge_no_token = EdgeDevice("edge_2")
        self.assertIsNone(self.tracer.trace_device(edge_no_token))

    async def test_full_simulation(self):
        """Test the full integrated simulation."""
        key_setup = KeySetup(num_iot_devices=2)
        group_elements = key_setup.run(self.issuer, self.verifier, self.edge_devices, self.iot_devices_per_edge)
        join = JoinPhase(group_elements)
        join.run(self.issuer, self.edge_devices, self.iot_devices_per_edge)
        attestation = AttestationPhase(group_elements)
        await attestation.run(self.verifier, self.edge_devices)
        verification = VerificationPhase(group_elements)
        results = await verification.run(self.verifier, self.edge_devices)
        
        traced_id = self.tracer.trace_device(self.edge)
        
        self.assertTrue(results["edge_1"])
        self.assertEqual(traced_id, "edge_1")

if __name__ == "__main__":
    unittest.main()