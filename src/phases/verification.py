from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import InternalVerifier, Issuer, EdgeDevice, IoTDevice
from charm.toolbox.pairinggroup import G1, G2
import asyncio

class VerificationPhase:
    def __init__(self, group_elements, phase_data=None):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements
        self.phase_data = phase_data

    def verify_signature(self, verifier, edge, signature, message="attestation_request"):
        s, c, R_total = signature
        total_pk = edge.public_key
        for iot in edge.connected_iot_devices:
            total_pk = self.crypto.ec_add(total_pk, iot.public_key)
        
        left = self.crypto.ec_multiply(s, self.group_elements['G_0'], G1)
        right = self.crypto.ec_add(R_total, self.crypto.ec_multiply(c, total_pk, G1))
        computed_c = self.crypto.hash_to_Zq(R_total, message)
        
        result = left == right and c == computed_c
        self.phase_data.append({
            "Phase": "Verification",
            "Device_ID": edge.device_id,
            "s": str(s),
            "c": str(c),
            "R_total": str(R_total),
            "Left": str(left),
            "Right": str(right),
            "Computed_c": str(computed_c),
            "Result": result,
            "Inputs": (
                [f"{edge.device_id}.signature", "G_0"] +
                [f"{edge.device_id}.public_key"] +
                [f"{iot.device_id}.public_key" for iot in edge.connected_iot_devices]
            ),
            "Outputs": [f"{edge.device_id}.verification_result"]
        })
        return result

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

async def test_verification_phase():
    from phases.key_setup import KeySetup
    from phases.join import JoinPhase
    from phases.attestation import AttestationPhase
    issuer = Issuer()
    verifier = InternalVerifier()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    attestation = AttestationPhase(group_elements)
    await attestation.run(verifier, edge_devices)
    verification = VerificationPhase(group_elements)
    results = await verification.run(verifier, edge_devices)
    assert all(results.values())
    print("Verification phase completed successfully.")

if __name__ == "__main__":
    asyncio.run(test_verification_phase())