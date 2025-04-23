import logging
from src.protocols.attestation import attest_device
from src.protocols.verification import verify_signature

def simulate_can_bus(key_setup_result, join_result):
    """Simulate CAN bus message broadcast and verification."""
    logging.info("Starting CAN bus simulation")
    messages = []
    
    for edge in join_result['edges']:
        # Each edge broadcasts a message with a DAA-A signature
        signature = attest_device(edge, key_setup_result, join_result)
        message = {
            'sender': edge.id,
            'payload': edge.iots,  # Payload is the list of IoT IDs
            'signature': signature
        }
        
        # Log the broadcast
        logging.info(f"Edge {edge.id} broadcast message: {edge.id}, payload size: {len(edge.iots)}")
        
        # Verify the message
        is_valid = verify_signature(signature, key_setup_result, join_result, edge, edge.tpm_policy)
        logging.info(f"Message from {edge.id} verification: {'Success' if is_valid else 'Failed'}")
        
        messages.append(message)
    
    logging.info("CAN bus simulation completed")
    return messages