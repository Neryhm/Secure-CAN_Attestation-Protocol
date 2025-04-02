import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.tpm_emulator import TPMEmulator

phase_data = []  # Global list to store debug prints
class IoTDevice:
    """Represents an IoT device (e.g., ECU) in the SPARK protocol."""
    
    def __init__(self, device_id):
        self.device_id = device_id
        self.crypto = CryptoPrimitives()
        self.private_key = None  # To be set in Join phase (sk_i)
        self.public_key = None  # PK_i = sk_i * G_0
        self.branch_key = None  # bk_i from Edge device
        self.credential = None  # Credential from Issuer

    def set_branch_key(self, branch_key):
        """Set the branch key received from the Edge device."""
        self.branch_key = branch_key

    def set_credential(self, credential):
        """Set the credential issued during Join phase."""
        self.credential = credential


class EdgeDevice:
    """Represents an Edge device (e.g., Zonal Gateway) with TPM."""
    
    def __init__(self, device_id):
        self.device_id = device_id
        self.crypto = CryptoPrimitives()
        self.tpm = TPMEmulator()
        self.tpm.initialize()  # TPM sets its own keys
        self.private_key = self.tpm.private_key  # Use TPM's private key
        self.public_key = self.tpm.public_key   # Use TPM's public key
        self.credential = None
        self.branch_keys = {}
        self.connected_iot_devices = []
        self.tracing_token = None

    def add_iot_device(self, iot_device):
        """Connect an IoT device and assign a branch key."""
        self.connected_iot_devices.append(iot_device)
        branch_key = self.crypto.generate_random_Zq()  # bk_i
        self.branch_keys[iot_device.device_id] = branch_key
        iot_device.set_branch_key(branch_key)

    def set_credential(self, credential):
        """Set the credential issued during Join phase."""
        self.credential = credential


class InternalVerifier:
    """Represents the Internal Verifier (e.g., Central Gateway)."""
    
    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.issuer_public_key = None  # To be set in Key Setup
        self.attestation_results = {}  # Store verification results

    def set_issuer_public_key(self, issuer_public_key):
        """Set the Issuer's public key for verification."""
        self.issuer_public_key = issuer_public_key


class Issuer:
    """Represents the Issuer that generates keys and credentials."""
    
    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.private_key = self.crypto.generate_random_Zq()  # alpha
        self.public_key = self.crypto.ec_multiply(self.private_key, self.crypto.g1)  # X = alpha * G_0
        self.tracing_keypair = (None, None)  # (x_T, X_T) for tracing

    def generate_tracing_keypair(self):
        """Generate tracing key pair (x_T, X_T). See Section 7.5."""
        x_T = self.crypto.generate_random_Zq()
        X_T = self.crypto.ec_multiply(x_T, self.crypto.g1)
        self.tracing_keypair = (x_T, X_T)


class Tracer:
    """Represents the Tracer that identifies compromised devices."""
    
    def __init__(self, issuer_tracing_private_key):
        self.crypto = CryptoPrimitives()
        self.tracing_private_key = issuer_tracing_private_key  # x_T from Issuer
        self.token_to_device = {}  # Map decrypted tokens to device IDs

    def trace_device(self, edge_device):
        """Decrypt the tracing token and identify the Edge device."""
        if not hasattr(edge_device, 'tracing_token') or edge_device.tracing_token is None:
            return None
        
        # Decrypt the tracing token (C1, C2) using ElGamal
        C1, C2 = edge_device.tracing_token
        TK = self.crypto.elgamal_decrypt(self.tracing_private_key, (C1, C2), self.crypto.g1)
        
        # Store mapping (in practice, TK would be linked to device ID via a database)
        self.token_to_device[TK] = edge_device.device_id
        return edge_device.device_id
    

def test_entities():
    """Test the entity classes and their interactions."""
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
    
    # Simulate Join phase for tracing token
    from phases.join import JoinPhase
    join = JoinPhase({'G_0': edge_devices[0].crypto.g1})
    join.run(issuer, edge_devices, iot_devices)
    
    # Test tracing
    traced_id = tracer.trace_device(edge_devices[0])
    
    assert edge_devices[0].public_key == edge_devices[0].tpm.get_public_key(), "Edge TPM key mismatch"
    assert all(iot.branch_key in edge.branch_keys.values() for edge in edge_devices for iot in iot_devices[edge.device_id]), "Branch key not assigned"
    assert verifier.issuer_public_key == issuer.public_key, "Verifier key mismatch"
    assert tracer.tracing_private_key == issuer.tracing_keypair[0], "Tracer key mismatch"
    assert traced_id == "edge_1", "Tracing failed to identify device"
    
    print("Entity classes initialized and connected successfully.")
    for edge in edge_devices:
        print(f"Edge {edge.device_id} manages {len(edge.connected_iot_devices)} IoT devices.")
    print(f"Issuer public key: {issuer.public_key != None}")
    print(f"Traced device ID: {traced_id}")