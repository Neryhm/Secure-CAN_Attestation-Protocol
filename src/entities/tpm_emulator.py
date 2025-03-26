import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from charm.toolbox.pairinggroup import G1, G2

class TPMEmulator:
    """Software emulation of TPM 2.0 features for SPARK protocol."""

    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.private_key = None  # TPM signing key (x_0)
        self.public_key = None  # Public key (PK = x_0 * G_0)
        self.pcrs = {}  # Platform Configuration Registers (PCR) as a dict
        self.policy = None  # Policy for key usage (e.g., PCR state)
        self.commit_state = {}  # Store temporary values for TPM2_Commit

    def initialize(self):
        """Initialize TPM with a key pair and empty PCRs."""
        # Generate signing key (x_0) and public key (PK)
        # See Section 7.2.1: "TPM chooses the secret signing key x_0"
        self.private_key = self.crypto.generate_random_Zq()
        self.public_key = self.crypto.ec_multiply(self.private_key, self.crypto.g1, G1)
        # Initialize PCRs (e.g., 0-23, but we'll use a subset for simplicity)
        for i in range(8):  # Simulate 8 PCRs
            self.pcrs[i] = self.crypto.hash_to_Zq(b"initial_state")  # Default value

    def extend_pcr(self, pcr_index, measurement):
        """Extend a PCR with a new measurement (hash chaining).
        See Section 7.2.4: 'PCRs store measurements as chained hashes'"""
        if pcr_index not in self.pcrs:
            raise ValueError(f"Invalid PCR index: {pcr_index}")
        # Extend: PCR = H(PCR || measurement)
        current_value = self.pcrs[pcr_index]
        new_value = self.crypto.hash_to_Zq(current_value, measurement)
        self.pcrs[pcr_index] = new_value
        return new_value

    def set_policy(self, expected_pcr_values):
        """Set a policy requiring specific PCR values for key usage.
        See Section 7.2.4: 'PolicyPCR ensures signing key is inoperable if compromised'"""
        self.policy = expected_pcr_values  # Dict of {pcr_index: expected_value}

    def check_policy(self):
        """Check if current PCR state satisfies the policy."""
        if not self.policy:
            return True  # No policy set, always pass
        for pcr_index, expected_value in self.policy.items():
            if self.pcrs.get(pcr_index) != expected_value:
                return False
        return True

    def TPM2_Commit(self, E_point, basename=None):
        """Simulate TPM2_Commit for attestation or tracing.
        See Section 7.3 (Step 2) and 7.2.5: 'Using TPM2_Commit'"""
        if not self.check_policy():
            raise RuntimeError("TPM policy not satisfied. Cannot commit.")
        
        # Generate random omega_0
        omega_0 = self.crypto.generate_random_Zq()
        R = self.crypto.ec_multiply(omega_0, E_point, G1)  # R_0 = omega_0 * E_0'
        
        # If basename is provided (for tracing), compute K_0
        K = None
        if basename:
            J_T = self.crypto.hash_to_G1(basename)  # J_T = H_1(bsn_T)
            K = self.crypto.ec_multiply(omega_0, J_T, G1)  # K_0 = omega_0 * J_T
        
        # Store omega_0 for later TPM2_Sign
        self.commit_state['omega_0'] = omega_0
        return R, K

    def TPM2_Sign(self, challenge):
        """Simulate TPM2_Sign to produce a signature.
        See Section 7.3 (Step 9): 'TPM outputs a signature s_0'"""
        if not self.check_policy():
            raise RuntimeError("TPM policy not satisfied. Cannot sign.")
        
        if 'omega_0' not in self.commit_state:
            raise RuntimeError("TPM2_Commit must be called before TPM2_Sign.")
        
        omega_0 = self.commit_state.pop('omega_0')  # Retrieve and clear
        s_0 = omega_0 + challenge * self.private_key  # s_0 = omega_0 + c * x_0
        return s_0

    def get_public_key(self):
        """Return the TPM's public key."""
        return self.public_key

def test_tpm_emulator():
    """Test the TPM emulator functionality."""
    tpm = TPMEmulator()
    tpm.initialize()
    
    # Test PCR extension
    initial_pcr = tpm.pcrs[0]
    tpm.extend_pcr(0, b"software_update")
    assert tpm.pcrs[0] != initial_pcr, "PCR extension failed"
    print("PCR extension successful.")
    
    # Set policy AFTER extension
    expected_pcrs = {0: tpm.pcrs[0]}
    tpm.set_policy(expected_pcrs)
    
    # Test TPM2_Commit and TPM2_Sign
    E_point = tpm.crypto.ec_multiply(tpm.crypto.generate_random_Zq(), tpm.crypto.g1)
    R, K = tpm.TPM2_Commit(E_point)
    challenge = tpm.crypto.hash_to_Zq(R, "test_message")
    s_0 = tpm.TPM2_Sign(challenge)
    
    # Verify signature: s_0 * E = R + c * (x_0 * E)
    left = tpm.crypto.ec_multiply(s_0, E_point)
    right = tpm.crypto.ec_add(R, tpm.crypto.ec_multiply(challenge, tpm.crypto.ec_multiply(tpm.private_key, E_point)))
    assert left == right, "TPM signature verification failed"
    print("TPM2_Commit and TPM2_Sign successful.")

if __name__ == "__main__":
    test_tpm_emulator()