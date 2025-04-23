import logging
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from src.config import PAIRING_GROUP

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