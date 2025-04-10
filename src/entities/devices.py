import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.tpm_emulator import TPMEmulator

# Global log for phase data
phase_data = []

class IoTDevice:
    def __init__(self, device_id):
        self.device_id = device_id
        self.crypto = CryptoPrimitives()
        self.private_key = None
        self.public_key = None
        self.branch_key = None
        self.credential = None

    def set_branch_key(self, branch_key):
        self.branch_key = branch_key

    def set_credential(self, credential):
        self.credential = credential

class EdgeDevice:
    def __init__(self, device_id):
        self.device_id = device_id
        self.crypto = CryptoPrimitives()
        self.tpm = TPMEmulator()
        self.tpm.initialize()
        self.private_key = self.tpm.private_key
        self.public_key = self.tpm.public_key
        self.credential = None
        self.branch_keys = {}
        self.connected_iot_devices = []
        self.tracing_token = None

    def add_iot_device(self, iot_device):
        self.connected_iot_devices.append(iot_device)
        branch_key = self.crypto.generate_random_Zq()
        self.branch_keys[iot_device.device_id] = branch_key
        iot_device.set_branch_key(branch_key)

    def set_credential(self, credential):
        self.credential = credential

class InternalVerifier:
    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.issuer_public_key = None
        self.attestation_results = {}

    def set_issuer_public_key(self, issuer_public_key):
        self.issuer_public_key = issuer_public_key

class Issuer:
    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.private_key = self.crypto.generate_random_Zq()
        self.public_key = self.crypto.ec_multiply(self.private_key, self.crypto.g1)
        self.tracing_keypair = (None, None)

    def generate_tracing_keypair(self):
        x_T = self.crypto.generate_random_Zq()
        X_T = self.crypto.ec_multiply(x_T, self.crypto.g1)
        self.tracing_keypair = (x_T, X_T)

class Tracer:
    def __init__(self, issuer_tracing_private_key):
        self.crypto = CryptoPrimitives()
        self.tracing_private_key = issuer_tracing_private_key
        self.token_to_device = {}

    def trace_device(self, edge_device):
        if not hasattr(edge_device, 'tracing_token') or edge_device.tracing_token is None:
            return None
        C1, C2 = edge_device.tracing_token
        TK = self.crypto.elgamal_decrypt(self.tracing_private_key, (C1, C2), self.crypto.g1)
        self.token_to_device[TK] = edge_device.device_id
        return edge_device.device_id

def test_entities():
    issuer = Issuer()
    verifier = InternalVerifier()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    
    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])
    
    verifier.set_issuer_public_key(issuer.public_key)
    for edge in edge_devices:
        for iot in iot_devices[edge.device_id]:
            edge.add_iot_device(iot)
    
    from phases.join import JoinPhase
    join = JoinPhase({'G_0': edge_devices[0].crypto.g1})
    join.run(issuer, edge_devices, iot_devices)
    
    traced_id = tracer.trace_device(edge_devices[0])
    
    assert edge_devices[0].public_key == edge_devices[0].tpm.get_public_key()
    assert all(iot.branch_key in edge.branch_keys.values() for edge in edge_devices for iot in iot_devices[edge.device_id])
    assert verifier.issuer_public_key == issuer.public_key
    assert tracer.tracing_private_key == issuer.tracing_keypair[0]
    assert traced_id == "edge_1"
    
    print("Entity classes initialized and connected successfully.")
    for edge in edge_devices:
        print(f"Edge {edge.device_id} manages {len(edge.connected_iot_devices)} IoT devices.")

if __name__ == "__main__":
    test_entities()