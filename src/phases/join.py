import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import Issuer, EdgeDevice, IoTDevice, InternalVerifier
from charm.toolbox.pairinggroup import G1, G2

class JoinPhase:
    def __init__(self, group_elements, phase_data=None):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements
        self.phase_data = phase_data

    def issue_credential(self, issuer, device):
        r = self.crypto.generate_random_Zq()
        A = self.crypto.ec_multiply(r, self.group_elements['G_0'], G1)
        B = self.crypto.ec_multiply(r, device.public_key, G1)
        s, c = self.crypto.schnorr_sign(issuer.private_key, (A, B), self.group_elements['G_0'])
        credential = (A, B, s, c)
        device.set_credential(credential)
        self.phase_data.append({
            "Phase": "Join_Credential",
            "Device_ID": device.device_id,
            "Credential": str(credential),
            "Inputs": ["issuer.private_key", f"{device.device_id}.public_key", "G_0"],  # Used to compute credential
            "Outputs": [f"{device.device_id}.credential"]  # Unique output per device
        })
        return credential

    def generate_tracing_token(self, issuer, edge_device):
        tk_base = self.crypto.generate_random_Zq()
        TK = self.crypto.ec_multiply(tk_base, self.group_elements['G_0'], G1)
        x_T, X_T = issuer.tracing_keypair
        encrypted_TK = self.crypto.elgamal_encrypt(X_T, TK, self.group_elements['G_0'])
        self.phase_data.append({
            "Phase": "Join_Tracing",
            "Device_ID": edge_device.device_id,
            "Tracing_Token": str(encrypted_TK),
            "Inputs": ["issuer.tracing_keypair", "G_0"],
            "Outputs": [f"{edge_device.device_id}.tracing_token"]
        })
        return encrypted_TK

    def run(self, issuer, edge_devices, iot_devices_per_edge):
        for edge in edge_devices:
            self.issue_credential(issuer, edge)
            edge.tracing_token = self.generate_tracing_token(issuer, edge)
            for iot in iot_devices_per_edge[edge.device_id]:
                edge.add_iot_device(iot)
                self.issue_credential(issuer, iot)

def test_join_phase():
    from phases.key_setup import KeySetup
    issuer = Issuer()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    verifier = InternalVerifier()
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    assert all(edge.credential is not None for edge in edge_devices)
    assert all(iot.credential is not None for edge in edge_devices for iot in iot_devices_per_edge[edge.device_id])
    assert all(hasattr(edge, 'tracing_token') for edge in edge_devices)
    print("Join phase completed successfully.")

if __name__ == "__main__":
    test_join_phase()