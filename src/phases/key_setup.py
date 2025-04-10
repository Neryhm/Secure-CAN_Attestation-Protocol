import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice
from charm.toolbox.pairinggroup import G1, G2

class KeySetup:
    def __init__(self, num_iot_devices=20, phase_data=None):
        self.crypto = CryptoPrimitives()
        self.num_iot_devices = num_iot_devices
        self.group_elements = {}
        self.phase_data = phase_data

    def generate_group_elements(self):
        self.group_elements['G_0'] = self.crypto.g1
        for i in range(1, self.num_iot_devices + 1):
            self.group_elements[f'G_{i}'] = self.crypto.group.random(G1)
        self.group_elements['H_0'] = self.crypto.group.random(G1)
        self.group_elements['H_1'] = self.crypto.group.random(G1)
        self.group_elements['G_0_bar'] = self.crypto.g2
        self.phase_data.append({
            "Phase": "KeySetup_Generate",
            "Group_Elements": {k: str(v) for k, v in self.group_elements.items()},
            "Inputs": [],  # No inputs; these are generated from scratch
            "Outputs": list(self.group_elements.keys())  # e.g., ["G_0", "G_1", ..., "H_0", "H_1", "G_0_bar"]
        })

    def setup_issuer(self, issuer):
        issuer.generate_tracing_keypair()
        self.phase_data.append({
            "Phase": "KeySetup_Issuer",
            "Issuer_Private": str(issuer.private_key),
            "Issuer_Public": str(issuer.public_key),
            "Tracing_Keypair": str(issuer.tracing_keypair),
            "Inputs": [],  # No direct inputs from prior steps
            "Outputs": ["issuer.private_key", "issuer.public_key", "issuer.tracing_keypair"]
        })

    def setup_verifier(self, verifier, issuer):
        verifier.set_issuer_public_key(issuer.public_key)
        self.phase_data.append({
            "Phase": "KeySetup_Verifier",
            "Issuer_Public": str(verifier.issuer_public_key),
            "Inputs": ["issuer.public_key"],  # Comes from issuer setup
            "Outputs": ["verifier.issuer_public_key"]
        })

    def setup_edge_device(self, edge_device):
        pass

    def setup_iot_device(self, iot_device):
        iot_device.private_key = self.crypto.generate_random_Zq()
        iot_device.public_key = self.crypto.ec_multiply(iot_device.private_key, self.crypto.g1)
        self.phase_data.append({
            "Phase": "KeySetup_IoT",
            "Device_ID": iot_device.device_id,
            "Private_Key": str(iot_device.private_key),
            "Public_Key": str(iot_device.public_key),
            "Inputs": ["G_0"],
            "Outputs": [f"{iot_device.device_id}.private_key", f"{iot_device.device_id}.public_key"]
        })

    def run(self, issuer, verifier, edge_devices, iot_devices_per_edge):
        self.generate_group_elements()
        self.setup_issuer(issuer)
        self.setup_verifier(verifier, issuer)

        for edge in edge_devices:
            self.setup_edge_device(edge)
            self.phase_data.append({
                "Phase": "KeySetup_Edge",
                "Device_ID": edge.device_id,
                "TPM_Private": str(edge.tpm.private_key),
                "TPM_Public": str(edge.tpm.public_key),
                "Inputs": ["G_0"],
                "Outputs": [f"{edge.device_id}.tpm.private_key", f"{edge.device_id}.tpm.public_key"]
            })
            for iot in iot_devices_per_edge[edge.device_id]:
                self.setup_iot_device(iot)
                edge.add_iot_device(iot)
        return self.group_elements

def test_key_setup():
    issuer = Issuer()
    verifier = InternalVerifier()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    assert 'G_0' in group_elements and 'G_20' in group_elements
    assert issuer.public_key is not None
    assert verifier.issuer_public_key == issuer.public_key
    assert all(len(edge.connected_iot_devices) == 5 for edge in edge_devices)
    print("Key Setup phase completed successfully.")

if __name__ == "__main__":
    test_key_setup()