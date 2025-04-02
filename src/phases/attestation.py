from crypto.primitives import CryptoPrimitives
from entities.devices import EdgeDevice, IoTDevice, InternalVerifier, Issuer
from network.comms import NetworkSimulator
from charm.toolbox.pairinggroup import G1, G2
import asyncio

phase_data = []  # Global list to store debug prints

class AttestationPhase:
    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements
        self.network = NetworkSimulator()

    async def generate_iot_signature(self, iot_device, edge_id, message):
        r = self.crypto.generate_random_Zq()
        R = self.crypto.ec_multiply(r, self.group_elements['G_0'], G1)
        data = await self.network.send_message(iot_device.device_id, edge_id, 64, (r, R))
        phase_data.append({"Phase": "Attestation_IoT", "Device_ID": iot_device.device_id, "r": str(r), "R": str(R)})
        return data
    
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
                s_total += r + c * iot.private_key
            
            # Create the 3-tuple signature
            sigma = (s_total, c, R_total)
            sigma_sent = await self.network.send_message(edge.device_id, "verifier", 128, sigma)
            aggregated_signatures[edge.device_id] = sigma_sent
            phase_data.append({"Phase": "Attestation_Edge", "Device_ID": edge.device_id, "Signature": str(sigma_sent)})
        
        verifier.attestation_results = aggregated_signatures
        return aggregated_signatures

# Test code (optional)
async def test_attestation_phase():
    from phases.key_setup import KeySetup
    from phases.join import JoinPhase
    
    issuer = Issuer()
    verifier = InternalVerifier()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    
    attestation = AttestationPhase(group_elements)
    signatures = await attestation.run(verifier, edge_devices)
    
    assert all(edge_id in signatures for edge_id in [f"edge_{i+1}" for i in range(4)]), "Edge signature missing"
    assert len(signatures["edge_1"]) == 3, "Invalid signature format"  # Expecting (s, c, R)
    print("Attestation phase with network simulation completed successfully.")

if __name__ == "__main__":
    asyncio.run(test_attestation_phase())