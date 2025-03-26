import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from src.entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice
from charm.toolbox.pairinggroup import G1, G2

class KeySetup:
    """Implements the Key Setup phase of the SPARK protocol."""

    def __init__(self, num_iot_devices=2):
        self.crypto = CryptoPrimitives()
        self.num_iot_devices = num_iot_devices  # Number of IoT devices per Edge
        self.group_elements = {}  # Public group elements (G_0, G_1, ..., G_n)

    def generate_group_elements(self):
        """Generate public group elements G_0, G_1, ..., G_n and H_0, H_1.
        See Section 7.2.1: 'Setup generates public parameters'"""
        # G_0 is already in CryptoPrimitives as g1
        self.group_elements['G_0'] = self.crypto.g1
        # Generate additional G_i elements for credentials and signatures
        for i in range(1, self.num_iot_devices + 1):
            self.group_elements[f'G_{i}'] = self.crypto.group.random(G1)
        # H_0 and H_1 for tracing and zero-knowledge proofs
        self.group_elements['H_0'] = self.crypto.group.random(G1)
        self.group_elements['H_1'] = self.crypto.group.random(G1)
        # G_0_bar (in G2) is already in CryptoPrimitives as g2
        self.group_elements['G_0_bar'] = self.crypto.g2

    def setup_issuer(self, issuer):
        """Set up the Issuer's key pair and tracing keys.
        See Section 7.2.1: 'Issuer chooses alpha <- Z_q'"""
        # Issuer's key pair (alpha, X) is already generated in Issuer.__init__
        # Generate tracing key pair (x_T, X_T)
        issuer.generate_tracing_keypair()

    def setup_verifier(self, verifier, issuer):
        """Provide the Internal Verifier with the Issuer's public key."""
        verifier.set_issuer_public_key(issuer.public_key)

    def setup_edge_device(self, edge_device):
        """Initialize Edge device with a key pair (to be certified in Join).
        See Section 7.2.1: 'TPM chooses secret signing key x_0'"""
        # TPM key pair (x_0, PK) is already set in TPMEmulator.initialize()
        # For simulation, generate an additional key pair for Edge (sk_0, PK_0)
        # edge_device.private_key = self.crypto.generate_random_Zq()
        # edge_device.public_key = self.crypto.ec_multiply(edge_device.private_key, self.crypto.g1)
        pass

    def setup_iot_device(self, iot_device):
        """Initialize IoT device with a key pair (to be certified in Join)."""
        iot_device.private_key = self.crypto.generate_random_Zq()
        iot_device.public_key = self.crypto.ec_multiply(iot_device.private_key, self.crypto.g1)

    def run(self, issuer, verifier, edge_devices, iot_devices_per_edge):
        """Execute the Key Setup phase for all entities."""
        # Generate public group elements
        self.generate_group_elements()
        
        # Setup Issuer and Verifier
        self.setup_issuer(issuer)
        self.setup_verifier(verifier, issuer)
        
        # Setup Edge devices and their connected IoT devices
        for edge in edge_devices:
            self.setup_edge_device(edge)
            iot_devices = iot_devices_per_edge[edge.device_id]
            for iot in iot_devices:
                self.setup_iot_device(iot)
                edge.add_iot_device(iot)  # Connect IoT to Edge
        
        return self.group_elements

def test_key_setup():
    """Test the Key Setup phase."""
    # Initialize entities
    issuer = Issuer()
    verifier = InternalVerifier()
    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    
    # Organize devices
    edge_devices = [edge1]
    iot_devices_per_edge = {"edge_1": [iot1, iot2]}
    
    # Run Key Setup
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    # Verify setup
    assert 'G_0' in group_elements and 'G_2' in group_elements, "Group elements missing"
    assert issuer.public_key is not None, "Issuer public key not set"
    assert verifier.issuer_public_key == issuer.public_key, "Verifier key mismatch"
    assert edge1.public_key is not None, "Edge public key not set"
    assert len(edge1.connected_iot_devices) == 2, "IoT devices not connected"
    assert iot1.private_key is not None, "IoT private key not set"
    
    print("Key Setup phase completed successfully.")
    print(f"Generated {len(group_elements)} group elements.")
    print(f"Edge device 'edge_1' connected to {len(edge1.connected_iot_devices)} IoT devices.")

if __name__ == "__main__":
    test_key_setup()