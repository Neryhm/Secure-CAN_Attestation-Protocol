from crypto.primitives import CryptoPrimitives
from entities.devices import InternalVerifier
from charm.toolbox.pairinggroup import G1, G2

class VerificationPhase:
    """Implements the Verification phase of the SPARK protocol."""

    def __init__(self, group_elements):
        self.crypto = CryptoPrimitives()
        self.group_elements = group_elements  # From Key Setup

    def verify_signature(self, verifier, edge_id, signature, message="attestation_request"):
        """Verify the aggregated signature for an Edge device."""
        s, c = signature  # Aggregated s and challenge c
        
        # Reconstruct R for verification (simplified from Attestation)
        # In real protocol, R is part of the signature; here we recompute for simplicity
        R = self.crypto.ec_multiply(s, self.group_elements['G_0'], G1) - \
            self.crypto.ec_multiply(c, verifier.issuer_public_key, G1)
        
        # Check if challenge matches: c = H(R || message)
        computed_c = self.crypto.hash_to_Zq(R, message)
        return c == computed_c

    def run(self, verifier, edge_devices, message="attestation_request"):
        """Execute the Verification phase."""
        results = {}
        
        for edge in edge_devices:
            edge_id = edge.device_id
            if edge_id in verifier.attestation_results:
                signature = verifier.attestation_results[edge_id]
                is_valid = self.verify_signature(verifier, edge_id, signature, message)
                results[edge_id] = is_valid
            else:
                results[edge_id] = False  # No signature to verify
        
        # Update verifier with results
        verifier.attestation_results = results
        return results

def test_verification_phase():
    """Test the Verification phase."""
    from phases.key_setup import KeySetup
    from phases.join import JoinPhase
    from phases.attestation import AttestationPhase
    
    # Setup entities
    issuer = Issuer()
    verifier = InternalVerifier()
    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    
    edge_devices = [edge1]
    iot_devices_per_edge = {"edge_1": [iot1, iot2]}
    
    # Run Key Setup
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    
    # Run Join
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    
    # Run Attestation
    attestation = AttestationPhase(group_elements)
    attestation.run(verifier, edge_devices)
    
    # Run Verification
    verification = VerificationPhase(group_elements)
    results = verification.run(verifier, edge_devices)
    
    # Verify
    assert "edge_1" in results, "Edge verification missing"
    assert results["edge_1"], "Signature verification failed"
    assert verifier.attestation_results["edge_1"], "Verifier results not updated"
    
    print("Verification phase completed successfully.")
    print(f"Verification results: {results}")

if __name__ == "__main__":
    test_verification_phase()