from crypto.primitives import CryptoPrimitives
from entities.devices import EdgeDevice, IoTDevice, InternalVerifier, Issuer
from network.comms import NetworkSimulator
from charm.toolbox.pairinggroup import G1, G2
import asyncio

class AttestationPhase:
    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements
        self.network = NetworkSimulator()

    async def generate_iot_signature(self, iot_device, edge_id, message):
        r = self.crypto.generate_random_Zq()
        R = self.crypto.ec_multiply(r, self.group_elements['G_0'], G1)
        return await self.network.send_message(iot_device.device_id, edge_id, 64, (r, R))

    async def run(self, verifier, edge_devices, message="attestation_request"):
        aggregated_signatures = {}
        
        for edge in edge_devices:
            edge.tpm.extend_pcr(0, message.encode())
            expected_pcrs = {0: edge.tpm.pcrs[0]}
            edge.tpm.set_policy(expected_pcrs)
            
            # Edge signature components
            r_edge = self.crypto.generate_random_Zq()
            R_edge = self.crypto.ec_multiply(r_edge, self.group_elements['G_0'], G1)
            
            # IoT signature components
            iot_tasks = [self.generate_iot_signature(iot, edge.device_id, message)
                         for iot in edge.connected_iot_devices]
            iot_signatures = await asyncio.gather(*iot_tasks)
            
            # Aggregate R values
            R_total = R_edge
            for _, R in iot_signatures:
                R_total = self.crypto.ec_add(R_total, R)
            
            # Compute challenge
            c = self.crypto.hash_to_Zq(R_total, message)
            
            # Aggregate s values
            s_total = r_edge + c * edge.tpm.private_key
            for iot, (r, _) in zip(edge.connected_iot_devices, iot_signatures):
                s_total += r + c * iot.branch_key
            
            # Create the 3-tuple signature
            sigma = (s_total, c, R_total)
            sigma_sent = await self.network.send_message(edge.device_id, "verifier", 128, sigma)
            aggregated_signatures[edge.device_id] = sigma_sent
        
        verifier.attestation_results = aggregated_signatures
        return aggregated_signatures

# Test code (optional)
async def test_attestation_phase():
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
    assert len(signatures["edge_1"]) == 3, "Invalid signature format"  # Expecting (s, c, R)
    print("Attestation phase with network simulation completed successfully.")

if __name__ == "__main__":
    asyncio.run(test_attestation_phase())