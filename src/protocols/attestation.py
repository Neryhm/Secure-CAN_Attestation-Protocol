from charm.toolbox.pairinggroup import PairingGroup, G1, ZR, pair
from src.config import PAIRING_GROUP
from src.crypto.ecc import H
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def attest_device(device, key_setup_result, join_result):
    """Generate DAA-A group signature for a device (Edge or IoT)."""
    G = key_setup_result['G']
    G_tilde = key_setup_result['G_tilde']
    issuer = join_result['issuer']
    X_tilde = issuer.public_key['X_tilde']  # Direct access, no indexing
    Y_tilde = issuer.public_key['Y_tilde']  # Direct access, no indexing
    credential = device.credential
    A, e, s = credential['A'], credential['e'], credential['s']
    
    # Randomize signature to ensure anonymity
    r = PAIRING_GROUP.random(ZR)
    T1 = A * r  # T1 = A^r
    T2 = G * r   # T2 = g^r
    
    # Compute Schnorr proof components
    k1 = PAIRING_GROUP.random(ZR)
    k2 = PAIRING_GROUP.random(ZR)
    R1 = G * k1
    R2 = pair(T1, X_tilde) ** k1 * pair(T2, Y_tilde) ** k2
    
    # Compute challenge
    c = H((T1, T2, R1, R2, device.public_key, device.tpm_policy if hasattr(device, 'tpm_policy') else {}))
    
    # Compute responses
    s1 = k1 + c * e
    s2 = k2 + c * s
    
    signature = {'T1': T1, 'T2': T2, 'c': c, 's1': s1, 's2': s2}
    
    logging.debug(f"Device {device.id}: DAA-A signature generated: {signature}")
    return signature