from crypto.primitives import CryptoPrimitives
from entities.devices import InternalVerifier, Issuer, EdgeDevice, IoTDevice
from charm.toolbox.pairinggroup import G1, G2
import asyncio

class VerificationPhase:
    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements

    def verify_signature(self, verifier, edge, signature, message="attestation_request"):
        s, c, R_total = signature
        total_pk = edge.public_key
        for iot in edge.connected_iot_devices:
            total_pk = self.crypto.ec_add(total_pk, iot.public_key)
        
        left = self.crypto.ec_multiply(s, self.group_elements['G_0'], G1)
        right = self.crypto.ec_add(R_total, self.crypto.ec_multiply(c, total_pk, G1))
        computed_c = self.crypto.hash_to_Zq(R_total, message)
        
        # Add debug prints
        print(f"Device: {edge.device_id}")
        print(f"  Left (s * G_0): {left}")
        print(f"  Right (R_total + c * total_pk): {right}")
        print(f"  Signature equation holds: {left == right}")
        print(f"  c from signature: {c}")
        print(f"  Computed c: {computed_c}")
        print(f"  Challenge matches: {c == computed_c}")
        print(f"  Connected IoT devices: {[iot.device_id for iot in edge.connected_iot_devices]}")
        
        return left == right and c == computed_c

    async def run(self, verifier, edge_devices, message="attestation_request"):
        results = {}
        
        for edge in edge_devices:
            edge_id = edge.device_id
            if edge_id in verifier.attestation_results:
                signature = verifier.attestation_results[edge_id]
                is_valid = self.verify_signature(verifier, edge, signature, message)
                results[edge_id] = is_valid
            else:
                results[edge_id] = False
        
        verifier.attestation_results = results
        return results

# Optional test code
async def test_verification_phase():
    from phases.key_setup import KeySetup
    from phases.join import JoinPhase
    from phases.attestation import AttestationPhase
    
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
    await attestation.run(verifier, edge_devices)
    
    verification = VerificationPhase(group_elements)
    results = await verification.run(verifier, edge_devices)
    
    print(f"Verification results: {results}")
    assert "edge_1" in results and results["edge_1"], "Verification failed"

if __name__ == "__main__":
    asyncio.run(test_verification_phase())