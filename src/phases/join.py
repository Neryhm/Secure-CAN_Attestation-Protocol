import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import Issuer, EdgeDevice, IoTDevice, InternalVerifier
from charm.toolbox.pairinggroup import G1, G2

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
            iot_devices = iot_devices_per_edge[edge.device_id]
            for iot in iot_devices:
                edge.add_iot_device(iot)  # Assigns branch key
                # Issue credential to IoT device (via Edge)
                self.issue_credential(issuer, iot)

def test_join_phase():
    """Test the Join phase."""
    # Setup from KeySetup (simplified)
    from phases.key_setup import KeySetup
    issuer = Issuer()
    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    verifier = InternalVerifier()
    
    edge_devices = [edge1]
    iot_devices_per_edge = {"edge_1": [iot1, iot2]}
    
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    # Run Join phase
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    
    # Verify
    assert edge1.credential is not None, "Edge credential not issued"
    assert iot1.credential is not None, "IoT1 credential not issued"
    assert iot2.branch_key in edge1.branch_keys.values(), "Branch key not assigned"
    assert hasattr(edge1, 'tracing_token'), "Tracing token not set"
    
    print("Join phase completed successfully.")
    print(f"Edge 'edge_1' has {len(edge1.connected_iot_devices)} IoT devices.")
    print(f"IoT devices have credentials: {iot1.credential is not None}, {iot2.credential is not None}")

if __name__ == "__main__":
    test_join_phase()