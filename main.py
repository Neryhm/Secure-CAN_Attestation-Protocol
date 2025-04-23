import logging
from src.config import EDGES, IOT_DEVICES
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase
from src.protocols.attestation import attest_device
from src.protocols.verification import verify_signature
from src.network.can_sim import simulate_can_bus
from src.entities.issuer import Issuer
from src.entities.tracer import Tracer
from src.entities.verifier import Verifier

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spark_protocol.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Run the full SPARK protocol."""
    logger.info("Starting SPARK protocol execution")

    # Initialize entities
    issuer = Issuer()
    tracer = Tracer()
    v_int = Verifier("V_int")
    v_ext = Verifier("V_ext")
    logger.info(f"Initialized {len(EDGES)} Edges, {len(IOT_DEVICES)} IoTs")

    # Key Setup
    try:
        logger.info("Executing key setup phase")
        key_setup_result = key_setup_phase(EDGES, IOT_DEVICES, issuer, tracer, v_int, v_ext)
        logger.info("Key setup completed")
    except Exception as e:
        logger.error(f"Key setup failed: {e}")
        raise

    # Join Phase
    try:
        logger.info("Executing join phase")
        join_result = join_phase(key_setup_result)
        edges = join_result['edges']
        iots = join_result['iots']
        logger.info(f"Join phase completed: {len(edges)} Edges, {len(iots)} IoTs")
    except Exception as e:
        logger.error(f"Join phase failed: {e}")
        raise

    # Attestation
    try:
        logger.info("Executing attestation phase")
        signatures = {}
        message = "Attestation message"
        for edge in edges:
            signatures[edge.id] = attest_device(edge, key_setup_result, join_result, message)
            logger.info(f"Edge {edge.id} attested")
        for iot in iots.values():
            signatures[iot.id] = attest_device(iot, key_setup_result, join_result, message)
            logger.info(f"IoT {iot.id} attested")
    except Exception as e:
        logger.error(f"Attestation phase failed: {e}")
        raise

    # Verification
    try:
        logger.info("Executing verification phase")
        for edge in edges:
            is_valid = verify_signature(
                signatures[edge.id], key_setup_result, join_result, edge,
                message=message, device_policy=edge.tpm_policy
            )
            logger.info(f"Edge {edge.id} verification: {'Success' if is_valid else 'Failed'}")
            if not is_valid:
                logger.error(f"Verification failed for Edge {edge.id}")
        for iot in iots.values():
            is_valid = verify_signature(
                signatures[iot.id], key_setup_result, join_result, iot,
                message=message, device_policy=None
            )
            logger.info(f"IoT {iot.id} verification: {'Success' if is_valid else 'Failed'}")
            if not is_valid:
                logger.error(f"Verification failed for IoT {iot.id}")
    except Exception as e:
        logger.error(f"Verification phase failed: {e}")
        raise

    # CAN Simulation
    try:
        logger.info("Executing CAN bus simulation")
        messages = simulate_can_bus(key_setup_result, join_result)
        logger.info(f"CAN simulation completed: {len(messages)} messages")
    except Exception as e:
        logger.error(f"CAN simulation failed: {e}")
        raise

    logger.info("SPARK protocol execution completed")

if __name__ == '__main__':
    main()