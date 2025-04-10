import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.crypto.primitives import CryptoPrimitives
from charm.toolbox.pairinggroup import G1, G2

# Global log
phase_data = []

class TPMEmulator:
    def __init__(self):
        self.crypto = CryptoPrimitives()
        self.private_key = None
        self.public_key = None
        self.pcrs = {}
        self.policy = None
        self.commit_state = {}

    def initialize(self):
        self.private_key = self.crypto.generate_random_Zq()
        self.public_key = self.crypto.ec_multiply(self.private_key, self.crypto.g1, G1)
        for i in range(8):
            self.pcrs[i] = self.crypto.hash_to_Zq(b"initial_state")
        phase_data.append({"Phase": "TPM_Init", "Device": "TPM", "Private_Key": str(self.private_key), "Public_Key": str(self.public_key)})

    def extend_pcr(self, pcr_index, measurement):
        if pcr_index not in self.pcrs:
            raise ValueError(f"Invalid PCR index: {pcr_index}")
        current_value = self.pcrs[pcr_index]
        new_value = self.crypto.hash_to_Zq(current_value, measurement)
        self.pcrs[pcr_index] = new_value
        phase_data.append({"Phase": "TPM_PCR_Extend", "PCR_Index": pcr_index, "New_Value": str(new_value)})
        return new_value

    def set_policy(self, expected_pcr_values):
        self.policy = expected_pcr_values
        phase_data.append({"Phase": "TPM_Set_Policy", "Policy": str(expected_pcr_values)})

    def check_policy(self):
        if not self.policy:
            return True
        for pcr_index, expected_value in self.policy.items():
            if self.pcrs.get(pcr_index) != expected_value:
                return False
        return True

    def TPM2_Commit(self, E_point, basename=None):
        if not self.check_policy():
            raise RuntimeError("TPM policy not satisfied.")
        omega_0 = self.crypto.generate_random_Zq()
        R = self.crypto.ec_multiply(omega_0, E_point, G1)
        K = None
        if basename:
            J_T = self.crypto.hash_to_G1(basename)
            K = self.crypto.ec_multiply(omega_0, J_T, G1)
        self.commit_state['omega_0'] = omega_0
        phase_data.append({"Phase": "TPM_Commit", "R": str(R), "K": str(K) if K else None, "Omega_0": str(omega_0)})
        return R, K

    def TPM2_Sign(self, challenge):
        if not self.check_policy():
            raise RuntimeError("TPM policy not satisfied.")
        if 'omega_0' not in self.commit_state:
            raise RuntimeError("TPM2_Commit must be called before TPM2_Sign.")
        omega_0 = self.commit_state.pop('omega_0')
        s_0 = omega_0 + challenge * self.private_key
        phase_data.append({"Phase": "TPM_Sign", "Signature": str(s_0), "Challenge": str(challenge)})
        return s_0

    def get_public_key(self):
        return self.public_key

def test_tpm_emulator():
    tpm = TPMEmulator()
    tpm.initialize()
    initial_pcr = tpm.pcrs[0]
    tpm.extend_pcr(0, b"software_update")
    assert tpm.pcrs[0] != initial_pcr
    expected_pcrs = {0: tpm.pcrs[0]}
    tpm.set_policy(expected_pcrs)
    E_point = tpm.crypto.ec_multiply(tpm.crypto.generate_random_Zq(), tpm.crypto.g1)
    R, K = tpm.TPM2_Commit(E_point)
    challenge = tpm.crypto.hash_to_Zq(R, "test_message")
    s_0 = tpm.TPM2_Sign(challenge)
    left = tpm.crypto.ec_multiply(s_0, E_point)
    right = tpm.crypto.ec_add(R, tpm.crypto.ec_multiply(challenge, tpm.crypto.ec_multiply(tpm.private_key, E_point)))
    assert left == right
    print("TPM emulator tests passed.")

if __name__ == "__main__":
    test_tpm_emulator()