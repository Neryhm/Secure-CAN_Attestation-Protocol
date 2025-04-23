import logging
from charm.toolbox.pairinggroup import G1, G2, ZR
from src.config import PAIRING_GROUP, EDGES, IOT_DEVICES
from src.entities.edge import Edge
from src.entities.iot import IoT
from src.entities.issuer import Issuer
from src.entities.tracer import Tracer
from src.entities.verifier import Verifier

logger = logging.getLogger(__name__)

def key_setup_phase(edges, iot_devices, issuer, tracer, v_int, v_ext):
    """Implement Key Setup Phase (Section 7.1)."""
    logger.info("Starting Key Setup Phase")

    # Generate base points
    G0 = PAIRING_GROUP.random(G1)
    G0_tilde = PAIRING_GROUP.random(G2)
    logger.debug(f"Generated base points: G0={G0}, G0_tilde={G0_tilde}")

    # Generate public group elements for IoT devices
    max_iots = max(len(edge['iots']) for edge in edges)
    r_k = [PAIRING_GROUP.random(ZR) for _ in range(max_iots)]
    G_k = [r_k[k] * G0 for k in range(max_iots)]
    G_k_tilde = [r_k[k] * G0_tilde for k in range(max_iots)]
    logger.debug(f"Generated public group elements: G_k={G_k}, G_k_tilde={G_k_tilde}")

    # Generate G for Issuer credential
    r_G = PAIRING_GROUP.random(ZR)
    G = r_G * G0
    G_tilde = r_G * G0_tilde
    logger.debug(f"Generated Issuer elements: G={G}, G_tilde={G_tilde}")

    # Initialize entities
    issuer_obj = Issuer()
    tracer_obj = Tracer()
    v_int_obj = Verifier("V_int")
    v_ext_obj = Verifier("V_ext")
    edge_objs = [Edge(edge) for edge in edges]
    iot_objs = {iot_id: IoT(iot_id) for iot_id in iot_devices}

    # Generate keys
    issuer_obj.generate_keys(G_tilde)
    tracer_obj.generate_keys(G)
    v_int_obj.generate_tpm_key()
    v_ext_obj.generate_tpm_key()
    for edge in edge_objs:
        edge.generate_keys(G0)
    for iot_id, iot in iot_objs.items():
        k_index = int(iot_id.split('_D_')[-1]) - 1
        iot.generate_keys(G_k, k_index)

    # Update config with generated keys
    for i, edge in enumerate(edges):
        edge['tpm_key'] = edge_objs[i].tpm_key
        edge['public_key'] = edge_objs[i].public_key
        edge['tpm_policy'] = edge_objs[i].tpm_policy
    for iot_id in iot_devices:
        iot_devices[iot_id]['private_key'] = iot_objs[iot_id].private_key
        iot_devices[iot_id]['public_key'] = iot_objs[iot_id].public_key

    logger.info("Completed Key Setup Phase")
    return {
        'G0': G0,
        'G0_tilde': G0_tilde,
        'G_k': G_k,
        'G_k_tilde': G_k_tilde,
        'G': G,
        'G_tilde': G_tilde,
        'issuer': issuer_obj,
        'tracer': tracer_obj,
        'v_int': v_int_obj,
        'v_ext': v_ext_obj,
        'edges': edge_objs,
        'iots': iot_objs
    }