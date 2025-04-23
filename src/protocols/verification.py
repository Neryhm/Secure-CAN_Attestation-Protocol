import logging
from charm.toolbox.pairinggroup import ZR, G1, G2, pair
import sys
sys.path.append('../')
from config import PAIRING_GROUP
from crypto.ecc import H

logger = logging.getLogger(__name__)

def verify_signature(signature, key_setup_result, join_result, device, message="", device_policy=None):
    """Verify DAA-A group signature with full CL credential."""
    logger.info(f"Verifying DAA-A signature for device {device.id}")

    # Extract key setup and join results
    G = key_setup_result['G']
    G_tilde = key_setup_result['G_tilde']
    G0 = key_setup_result['G0']
    G_k = key_setup_result['G_k']
    issuer = join_result['issuer']
    X_tilde = issuer.public_key['X_tilde']
    Y_tilde = issuer.public_key['Y_tilde']
    
    # Extract signature components
    T1, T2, T3, T4, T5, c, s1, s2, s3 = (
        signature['T1'], signature['T2'], signature['T3'], signature['T4'],
        signature['T5'], signature['c'], signature['s1'], signature['s2'], signature['s3']
    )

    # Recompute R1, R2, R3
    R1 = G * s1 - T2 * c
    R2 = (
        pair(T1, X_tilde) ** s1 * 
        pair(T2, Y_tilde) ** s2 * 
        pair(T3, G_tilde) ** s3 * 
        (pair(T1, G_tilde) ** (-c))
    )
    R3 = T4 * s3 - T4 * c

    # Verify challenge
    policy = device_policy if device_policy is not None else (device.tpm_policy if hasattr(device, 'tpm_policy') else {})
    computed_c = H((T1, T2, T3, T4, T5, R1, R2, R3, device.public_key, policy, message))
    if computed_c != c:
        logger.error(f"Device {device.id}: Signature verification failed: Invalid challenge")
        return False

    # Verify pairing equations
    if pair(T1, G_tilde) != pair(T2, X_tilde):
        logger.error(f"Device {device.id}: Signature verification failed: Pairing equation T1 invalid")
        return False
    if pair(T3, G_tilde) != pair(T2, Y_tilde):
        logger.error(f"Device {device.id}: Signature verification failed: Pairing equation T3 invalid")
        return False
    if pair(T4, G_tilde) != pair(G0, Y_tilde) * pair(T2, Y_tilde):
        logger.error(f"Device {device.id}: Signature verification failed: Pairing equation T4 invalid")
        return False
    for i, T5_i in enumerate(T5):
        if pair(T5_i, G_tilde) != pair(G_k[i], Y_tilde) * pair(T2, Y_tilde):
            logger.error(f"Device {device.id}: Signature verification failed: Pairing equation T5[{i}] invalid")
            return False

    logger.info(f"Device {device.id}: Signature verification succeeded")
    return True