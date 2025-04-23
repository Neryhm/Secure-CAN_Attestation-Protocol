import logging
from charm.toolbox.pairinggroup import G1, G2
import sys
sys.path.append('../')
from protocols.attestation import attest_device
from protocols.verification import verify_signature

logger = logging.getLogger(__name__)

def simulate_can_bus(key_setup_result, join_result):
    """Simulate CAN bus with full DAA-A signatures."""
    logger.info("Starting CAN bus simulation")
    messages = []
    
    for edge in join_result['edges']:
        message = "CAN message"
        signature = attest_device(edge, key_setup_result, join_result, message)
        msg = {
            'sender_id': edge.id,
            'payload': edge.iots,
            'signature': signature
        }
        is_valid = verify_signature(
            signature, key_setup_result, join_result, edge,
            message=message, device_policy=edge.tpm_policy
        )
        logger.info(f"Edge {edge.id} message verification: {'Success' if is_valid else 'Failed'}")
        messages.append(msg)
    
    logger.info(f"CAN bus simulation completed: {len(messages)} messages")
    return messages