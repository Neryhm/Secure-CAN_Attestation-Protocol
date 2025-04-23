from charm.toolbox.pairinggroup import PairingGroup, G1, G2, pair
from src.config import PAIRING_GROUP
from src.crypto.ecc import H
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def verify_signature(signature, key_setup_result, join_result, device, device_policy=None):
    """Verify DAA-A group signature."""
    G = key_setup_result['G']
    G_tilde = key_setup_result['G_tilde']
    issuer = join_result['issuer']
    X_tilde = issuer.public_key['X_tilde']
    Y_tilde = issuer.public_key['Y_tilde']
    
    T1, T2, c, s1, s2 = signature['T1'], signature['T2'], signature['c'], signature['s1'], signature['s2']
    
    # Recompute R1, R2
    R1 = G * s1 - T2 * c
    R2 = pair(T1, X_tilde) ** s1 * pair(T2, Y_tilde) ** s2 / pair(T1, G_tilde) ** c
    
    # Verify challenge
    computed_c = H((T1, T2, R1, R2, device.public_key, device_policy or {}))
    if computed_c != c:
        logging.error("Signature verification failed: Invalid challenge")
        return False
    
    # Verify pairing equation
    if pair(T1, G_tilde) != pair(T2, X_tilde):
        logging.error("Signature verification failed: Pairing equation invalid")
        return False
    
    logging.info("Signature verification succeeded")
    return True