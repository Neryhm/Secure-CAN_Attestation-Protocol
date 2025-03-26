from crypto.primitives import CryptoPrimitives
from entities.devices import EdgeDevice, IoTDevice, InternalVerifier, Issuer
from network.comms import NetworkSimulator
from charm.toolbox.pairinggroup import G1, G2
import asyncio

class AttestationPhase:
    """Implements the Attestation phase with network simulation."""

    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements
        self.network = NetworkSimulator()

    async def generate_iot_signature(self, iot_device, edge_id, message):
        """Generate IoT signature with network delay."""
        s, c = self.crypto.schnorr_sign(iot_device.branch_key, message, self.group_elements['G_0'])
        # Simulate sending signature to Edge (64 bytes for simplicity)
        signature = (s, c)
        return await self.network.send_message(iot_device.device_id, edge_id, 64, signature)

    async def aggregate_signatures(self, edge_device, iot_signatures, edge_signature):
        """Aggregate signatures (no additional delay here)."""
        total_s = edge_signature[0]
        for sig in iot_signatures:
            total_s += sig[0]
        c = edge_signature[1]
        return (total_s, c)

    async def run(self, verifier, edge_devices, message="attestation_request"):
        """Execute the Attestation phase with network simulation."""
        aggregated_signatures = {}
        
        for edge in edge_devices:
            # Edge checks state via TPM
            edge.tpm.extend_pcr(0, message.encode())
            expected_pcrs = {0: edge.tpm.pcrs[0]}
            edge.tpm.set_policy(expected_pcrs)
            
            # TPM generates signature
            E_point = self.crypto.ec_multiply(self.crypto.generate_random_Zq(), self.group_elements['G_0'], G1)
            R, _ = edge.tpm.TPM2_Commit(E_point)
            challenge = self.crypto.hash_to_Zq(R, message)
            s_0 = edge.tpm.TPM2_Sign(challenge)
            edge_signature = (s_0, challenge)
            
            # Collect IoT signatures over network
            iot_tasks = [
                self.generate_iot_signature(iot, edge.device_id, message)
                for iot in edge.connected_iot_devices
            ]
            iot_signatures = await asyncio.gather(*iot_tasks)
            
            # Aggregate signatures
            sigma = await self.aggregate_signatures(edge, iot_signatures, edge_signature)
            
            # Send aggregated signature to Verifier (128 bytes for aggregated sig)
            sigma = await self.network.send_message(edge.device_id, "verifier", 128, sigma)
            aggregated_signatures[edge.device_id] = sigma
        
        verifier.attestation_results = aggregated_signatures
        return aggregated_signatures

async def test_attestation_phase():
    """Test the Attestation phase with network simulation."""
    from phases.key_setup import KeySetup
    from phases.join import JoinPhase
    
    issuer = Issuer()
    verifier = InternalVerifier()
    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    
    edge_devices = [edge1]
    iot_devices_per_edge = {"edge_1": [iot1, iot2]}
    
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    
    attestation = AttestationPhase(group_elements)
    signatures = await attestation.run(verifier, edge_devices)
    
    assert "edge_1" in signatures, "Edge signature missing"
    assert len(signatures["edge_1"]) == 2, "Invalid signature format"
    print("Attestation phase with network simulation completed successfully.")

if __name__ == "__main__":
    asyncio.run(test_attestation_phase())