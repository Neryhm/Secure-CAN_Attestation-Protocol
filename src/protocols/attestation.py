import logging
from charm.toolbox.pairinggroup import ZR, G1, pair
import sys
sys.path.append('../')
from config import PAIRING_GROUP
from crypto.ecc import H

logger = logging.getLogger(__name__)

def attest_device(device, key_setup_result, join_result, message=""):
    """Generate DAA-A group signature for a device (Edge or IoT) with full CL credential."""
    logger.info(f"Generating DAA-A signature for device {device.id}")

    # Extract key setup and join results
    G = key_setup_result['G']
    G_tilde = key_setup_result['G_tilde']
    G0 = key_setup_result['G0']
    G_k = key_setup_result['G_k']
    issuer = join_result['issuer']
    X_tilde = issuer.public_key['X_tilde']
    Y_tilde = issuer.public_key['Y_tilde']
    credential = device.credential
    A, B_cred, C, D, E0, E_k, challenge = (
        credential['A'], credential['B'], credential['C'], credential['D'],
        credential['E0'], credential['E_k'], credential['challenge']
    )

    # Randomize signature for anonymity
    r = PAIRING_GROUP.random(ZR)
    T1 = A * r  # T1 = A^r
    T2 = G * r  # T2 = G^r
    T3 = B_cred * r  # T3 = B^r
    T4 = E0 * r  # T4 = E0^r
    T5 = [E_k[i] * r for i in range(len(E_k))]  # T5 = [E_k[i]^r]

    # Compute Schnorr proof components
    k1 = PAIRING_GROUP.random(ZR)  # For e
    k2 = PAIRING_GROUP.random(ZR)  # For s
    k3 = PAIRING_GROUP.random(ZR)  # For t
    R1 = G * k1  # R1 = G^k1
    R2 = pair(T1, X_tilde) ** k1 * pair(T2, Y_tilde) ** k2 * pair(T3, G_tilde) ** k3
    R3 = T4 * k3  # R3 = E0^r * k3

    # Compute challenge
    policy = device.tpm_policy if hasattr(device, 'tpm_policy') else {}
    c = H((T1, T2, T3, T4, T5, R1, R2, R3, device.public_key, policy, message))
    
    # Compute responses
    s1 = k1 + c * credential['challenge']  # Use stored challenge
    s2 = k2 + c * device.private_key  # Assuming private_key is s or equivalent
    s3 = k3 + c * r

    signature = {
        'T1': T1, 'T2': T2, 'T3': T3, 'T4': T4, 'T5': T5,
        'c': c, 's1': s1, 's2': s2, 's3': s3
    }
    
    logger.debug(f"Device {device.id}: DAA-A signature generated: {signature}")
    return signature