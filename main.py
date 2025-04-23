import logging
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase
from src.protocols.attestation import attest_device
from src.protocols.verification import verify_signature
from src.network.can_sim import simulate_can_bus
from src.entities.issuer import Issuer
from src.entities.tracer import Tracer
from src.entities.verifier import Verifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spark_protocol.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Run the full SPARK protocol: key setup, join, attestation, verification, and CAN simulation."""
    logging.info("Starting SPARK protocol execution")

    # Initialize entities
    iot_counts = [3, 4, 5, 6]  # IoTs per Edge
    edges = []
    iot_devices = {}
    for i, iot_count in enumerate(iot_counts, 1):
        edge_id = f"Edge_{i}"
        iot_ids = [f"{edge_id}_D_{j+1}" for j in range(iot_count)]
        edge_data = {
            'id': edge_id,
            'iots': iot_ids,
            'tpm_key': None,
            'public_key': None,
            'tpm_policy': None
        }
        edges.append(edge_data)
        for iot_id in iot_ids:
            iot_devices[iot_id] = {}
    issuer = Issuer()
    tracer = Tracer()
    v_int = Verifier("V_int")
    v_ext = Verifier("V_ext")

    logging.info(f"Initialized {len(edges)} Edges, {len(iot_devices)} IoTs, Issuer, Tracer, V_int, V_ext")

    # Step 1: Key Setup
    logging.info("Executing key setup phase")
    key_setup_result = key_setup_phase(edges, iot_devices, issuer, tracer, v_int, v_ext)
    logging.info("Key setup completed")

    # Step 2: Join Phase
    logging.info("Executing join phase")
    join_result = join_phase(key_setup_result)
    edges = join_result['edges']
    iots = join_result['iots']
    logging.info(f"Join phase completed: {len(edges)} Edges, {len(iots)} IoTs")

    # Step 3: Attestation
    logging.info("Executing attestation phase")
    signatures = {}
    for edge in edges:
        signatures[edge.id] = attest_device(edge, key_setup_result, join_result)
        logging.info(f"Edge {edge.id} attested")
    for iot in iots.values():
        signatures[iot.id] = attest_device(iot, key_setup_result, join_result)
        logging.info(f"IoT {iot.id} attested")

    # Step 4: Verification
    logging.info("Executing verification phase")
    for edge in edges:
        is_valid = verify_signature(signatures[edge.id], key_setup_result, join_result, edge, edge.tpm_policy)
        logging.info(f"Edge {edge.id} signature verification: {'Success' if is_valid else 'Failed'}")
        if not is_valid:
            logging.error(f"Verification failed for Edge {edge.id}")
    for iot in iots.values():
        is_valid = verify_signature(signatures[iot.id], key_setup_result, join_result, iot)
        logging.info(f"IoT {iot.id} signature verification: {'Success' if is_valid else 'Failed'}")
        if not is_valid:
            logging.error(f"Verification failed for IoT {iot.id}")

    # Step 5: CAN Simulation
    logging.info("Executing CAN bus simulation")
    messages = simulate_can_bus(key_setup_result, join_result)
    logging.info(f"CAN simulation completed: {len(messages)} messages processed")

    logging.info("SPARK protocol execution completed")

if __name__ == '__main__':
    main()