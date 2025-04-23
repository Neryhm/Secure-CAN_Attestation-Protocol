import logging
from charm.toolbox.pairinggroup import G1, G2, GT, ZR
import sys
sys.path.append('../')
from config import PAIRING_GROUP, EDGES, IOT_DEVICES
from entities.edge import Edge
from entities.iot import IoT
from entities.issuer import Issuer
from entities.tracer import Tracer
from entities.verifier import Verifier
from crypto.ecc import verify_schnorr_proof

logger = logging.getLogger(__name__)

def key_setup_phase(edges, iot_devices, issuer, tracer, v_int, v_ext):
    """Implement Key Setup Phase (Section 7.1) with Schnorr proofs."""
    logger.info("Starting Key Setup Phase")

    # Define mathematical objects
    E = G1  # Elliptic curve E
    E_tilde = G2  # Twisted curve E_tilde
    F_tilde = GT  # Target group F_tilde
    logger.debug(f"Mathematical objects: E={E}, E_tilde={E_tilde}, F_tilde={F_tilde}")

    # Generate base points
    G0 = PAIRING_GROUP.random(G1)  # Base point in E
    G0_tilde = PAIRING_GROUP.random(G2)  # Base point in E_tilde
    logger.debug(f"Base points: G0={G0}, G0_tilde={G0_tilde}")

    # Generate public group elements for IoT devices
    max_iots = max(len(edge['iots']) for edge in edges)  # n = 6
    r_k = [PAIRING_GROUP.random(ZR) for _ in range(max_iots)]  # Random scalars
    G_k = [r_k[k] * G0 for k in range(max_iots)]  # Public points in E
    G_k_tilde = [r_k[k] * G0_tilde for k in range(max_iots)]  # Public points in E_tilde
    logger.debug(f"Public group elements: r_k={r_k}, G_k={G_k}, G_k_tilde={G_k_tilde}")

    # Generate G for Issuer credential
    r_G = PAIRING_GROUP.random(ZR)
    G = r_G * G0  # Point in E
    G_tilde = r_G * G0_tilde  # Point in E_tilde
    logger.debug(f"Issuer elements: r_G={r_G}, G={G}, G_tilde={G_tilde}")

    # Initialize entities
    issuer_obj = Issuer()
    tracer_obj = Tracer()
    v_int_obj = Verifier("V_int")
    v_ext_obj = Verifier("V_ext")
    edge_objs = [Edge(edge) for edge in edges]
    iot_objs = {iot_id: IoT(iot_id) for iot_id in iot_devices}

    # Generate keys and proofs
    issuer_obj.generate_keys(G_tilde)
    tracer_obj.generate_keys(G)
    v_int_obj.generate_tpm_key()
    v_ext_obj.generate_tpm_key()
    for edge in edge_objs:
        edge.generate_keys(G0)
    for iot_id, iot in iot_objs.items():
        k_index = int(iot_id.split('_D_')[-1]) - 1
        iot.generate_keys(G_k, k_index)

    # Verify Schnorr proofs
    for iot_id, iot in iot_objs.items():
        k_index = int(iot_id.split('_D_')[-1]) - 1
        is_valid = verify_schnorr_proof(iot.public_key, G_k[k_index], iot.proof)
        logger.debug(f"IoT {iot_id} Schnorr proof valid: {is_valid}")
        assert is_valid, f"Schnorr proof failed for IoT {iot_id}"
    is_valid_x = verify_schnorr_proof(issuer_obj.public_key['X_tilde'], G_tilde, issuer_obj.proofs['X_tilde'])
    is_valid_y = verify_schnorr_proof(issuer_obj.public_key['Y_tilde'], G_tilde, issuer_obj.proofs['Y_tilde'])
    logger.debug(f"Issuer Schnorr proofs valid: X_tilde={is_valid_x}, Y_tilde={is_valid_y}")
    assert is_valid_x and is_valid_y, "Issuer Schnorr proofs failed"
    is_valid_tracer = verify_schnorr_proof(tracer_obj.public_key, G, tracer_obj.proof)
    logger.debug(f"Tracer Schnorr proof valid: {is_valid_tracer}")
    assert is_valid_tracer, "Tracer Schnorr proof failed"

    # Update config with generated keys
    for i, edge in enumerate(edges):
        edge['tpm_key'] = edge_objs[i].tpm_key
        edge['public_key'] = edge_objs[i].public_key
        edge['tpm_policy'] = edge_objs[i].tpm_policy
    for iot_id in iot_devices:
        iot_devices[iot_id]['private_key'] = iot_objs[iot_id].private_key
        iot_devices[iot_id]['public_key'] = iot_objs[iot_id].public_key
        iot_devices[iot_id]['proof'] = iot_objs[iot_id].proof

    logger.info("Completed Key Setup Phase")
    return {
        'E': E,
        'E_tilde': E_tilde,
        'F_tilde': F_tilde,
        'G0': G0,
        'G0_tilde': G0_tilde,
        'G_k': G_k,
        'G_k_tilde': G_k_tilde,
        'r_k': r_k,
        'G': G,
        'G_tilde': G_tilde,
        'r_G': r_G,
        'issuer': issuer_obj,
        'tracer': tracer_obj,
        'v_int': v_int_obj,
        'v_ext': v_ext_obj,
        'edges': edge_objs,
        'iots': iot_objs
    }