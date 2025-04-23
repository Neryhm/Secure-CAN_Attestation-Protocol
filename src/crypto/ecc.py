import logging
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sys
sys.path.append('../')
from config import PAIRING_GROUP

logger = logging.getLogger(__name__)

def H(*args):
    """Hash function mapping to ZR."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for arg in args:
        digest.update(str(arg).encode())
    result = PAIRING_GROUP.init(ZR, int.from_bytes(digest.finalize(), 'big') % PAIRING_GROUP.order())
    logger.debug(f"H({args}) = {result}")
    return result

def H1(data):
    """Hash function mapping to G1."""
    result = PAIRING_GROUP.hash(data.encode(), G1)
    logger.debug(f"H1({data}) = {result}")
    return result

def generate_schnorr_proof(private_key, public_key, base_point):
    """Generate Schnorr proof for public key."""
    r = PAIRING_GROUP.random(ZR)
    R = r * base_point
    c = H(base_point, public_key, R)
    sigma = r + c * private_key
    logger.debug(f"Schnorr proof: sigma={sigma}, c={c}, R={R}")
    return {'sigma': sigma, 'c': c, 'R': R}

def verify_schnorr_proof(public_key, base_point, proof):
    """Verify Schnorr proof."""
    sigma, c, R = proof['sigma'], proof['c'], proof['R']
    left = sigma * base_point
    right = R + c * public_key
    is_valid = left == right
    logger.debug(f"Schnorr verification: left={left}, right={right}, valid={is_valid}")
    return is_valid