import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import Issuer, EdgeDevice, IoTDevice, InternalVerifier
from charm.toolbox.pairinggroup import G1, G2

phase_data = []  # Global list to store debug prints

class JoinPhase:
    """Implements the Join phase of the SPARK protocol."""

    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements  # From Key Setup

    def issue_credential(self, issuer, device):
        """Issue a credential to a device using modified DAA-A scheme.
        See Section 7.2.2: 'Join protocol based on modified DAA-A'"""
        # Device commits to its public key
        r = self.crypto.generate_random_Zq()
        A = self.crypto.ec_multiply(r, self.group_elements['G_0'], G1)  # A = r * G_0
        B = self.crypto.ec_multiply(r, device.public_key, G1)  # B = r * PK

        # Issuer signs (simplified Schnorr-like credential)
        s, c = self.crypto.schnorr_sign(issuer.private_key, (A, B), self.group_elements['G_0'])
        credential = (A, B, s, c)

        # Device stores credential
        device.set_credential(credential)
        phase_data.append({"Phase": "Join_Credential", "Device_ID": device.device_id, "Credential": str(credential)})
        return credential

    def generate_tracing_token(self, issuer, edge_device):
        """Generate a tracing token for the Edge device.
        See Section 7.2.2 and 7.5: 'TPM generates tracing token TK'"""
        # TPM generates a random nonce as the tracing token base
        tk_base = self.crypto.generate_random_Zq()
        TK = self.crypto.ec_multiply(tk_base, self.group_elements['G_0'], G1)  # TK = tk_base * G_0
        
        # Encrypt TK with Issuer's tracing public key X_T
        x_T, X_T = issuer.tracing_keypair
        encrypted_TK = self.crypto.elgamal_encrypt(X_T, TK, self.group_elements['G_0'])
        phase_data.append({"Phase": "Join_Tracing", "Device_ID": edge_device.device_id, "Tracing_Token": str(encrypted_TK)})
        return encrypted_TK

    def run(self, issuer, edge_devices, iot_devices_per_edge):
        """Execute the Join phase for all devices."""
        # Enroll Edge devices
        for edge in edge_devices:
            # Issue credential to Edge device
            self.issue_credential(issuer, edge)
            
            # Generate tracing token for Edge
            edge.tracing_token = self.generate_tracing_token(issuer, edge)
            
            # Connect IoT devices to Edge
            for iot in iot_devices_per_edge[edge.device_id]:
                edge.add_iot_device(iot)  # Assigns branch key
                # Issue credential to IoT device (via Edge)
                self.issue_credential(issuer, iot)

def test_join_phase():
    """Test the Join phase."""
    # Setup from KeySetup (simplified)
    from phases.key_setup import KeySetup
    issuer = Issuer()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    verifier = InternalVerifier()
    
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    # Run Join phase
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    
    # Verify
    assert all(edge.credential is not None for edge in edge_devices), "Edge credential not issued"
    assert all(iot.credential is not None for edge in edge_devices for iot in iot_devices_per_edge[edge.device_id]), "IoT1 credential not issued"
    assert all(hasattr(edge, 'tracing_token') for edge in edge_devices), "Tracing token not set"
    
    print("Join phase completed successfully.")
if __name__ == "__main__":
    test_join_phase()