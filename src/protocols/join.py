import logging
from charm.toolbox.pairinggroup import ZR, G1
import sys
sys.path.append('../')
from config import PAIRING_GROUP
from crypto.ecc import H, H1, generate_schnorr_proof, verify_schnorr_proof
from crypto.tpm_sim import TPM

logger = logging.getLogger(__name__)

def join_phase(key_setup_result):
    """Implement Join Phase (Section 7.2) with full CL credential and revocation checks."""
    logger.info("Starting Join Phase")

    # Extract key setup results
    G = key_setup_result['G']
    G0 = key_setup_result['G0']
    G_k = key_setup_result['G_k']
    G_tilde = key_setup_result['G_tilde']
    issuer = key_setup_result['issuer']
    tracer = key_setup_result['tracer']
    edges = key_setup_result['edges']
    iots = key_setup_result['iots']
    x = issuer.private_key['x']  # Issuer private key x
    y = issuer.private_key['y']  # Issuer private key y

    # Initialize revocation list (mocked, should be in issuer.py)
    issuer.revocation_list = getattr(issuer, 'revocation_list', set())

    for edge in edges:
        logger.info(f"Processing Edge {edge.id}")

        # 7.2.1: Check Edge eligibility
        if edge.public_key in issuer.revocation_list:
            logger.error(f"Edge {edge.id}: Public key revoked")
            raise ValueError(f"Edge {edge.id} revoked")
        
        # Simulate TPM authorization session
        tpm = TPM(edge.tpm_key)
        nonce = PAIRING_GROUP.random(ZR)
        reg_package = tpm.create_registration_package(nonce, edge.public_key)
        tpm_signature = generate_schnorr_proof(edge.tpm_key, edge.public_key, G)
        if not verify_schnorr_proof(edge.public_key, G, tpm_signature):
            logger.error(f"Edge {edge.id}: Invalid TPM signature")
            raise ValueError(f"Edge {edge.id} TPM signature invalid")
        
        # Check TPM policy
        is_eligible = tpm.verify_policy(edge.tpm_policy)
        logger.debug(f"Edge {edge.id}: Eligibility check={is_eligible}")
        if not is_eligible:
            logger.error(f"Edge {edge.id}: TPM policy invalid")
            raise ValueError(f"Edge {edge.id} not eligible")

        # 7.2.2: Generate branch key B = PK + sum(X_k)
        iot_keys = [iots[iot_id].public_key for iot_id in edge.iots]
        B = edge.public_key + sum(iot_keys, G1.identity())  # Sum public keys
        edge.branch_key = B
        logger.debug(f"Edge {edge.id}: Branch key B={B}")

        # 7.2.3: Generate branch credential (full CL signature)
        t = PAIRING_GROUP.random(ZR)  # Random scalar for credential
        A = t * G
        B_cred = y * A
        C = x * A + t * x * y * B
        D = t * y * B
        E0 = t * y * G0
        E_k = [t * y * G_k[i] for i in range(len(edge.iots))]
        challenge = H(str(t * G) + ''.join(str(t * G_k[i]) for i in range(len(edge.iots))) + str(t * B))
        edge.credential = {
            'A': A, 'B': B_cred, 'C': C, 'D': D, 'E0': E0, 'E_k': E_k,
            'challenge': challenge, 'tpm_signature': tpm_signature
        }
        logger.debug(f"Edge {edge.id}: Credential CRE={edge.credential}")

        # Process IoT devices under this Edge
        for iot_id in edge.iots:
            iot = iots[iot_id]
            logger.info(f"Processing IoT {iot.id}")

            # Generate IoT credential (full CL signature)
            t_iot = PAIRING_GROUP.random(ZR)
            A_iot = t_iot * G
            B_iot = y * A_iot
            C_iot = x * A_iot + t_iot * x * y * B
            D_iot = t_iot * y * B
            E0_iot = t_iot * y * G0
            E_k_iot = [t_iot * y * G_k[i] for i in range(len(edge.iots))]
            challenge_iot = H(str(t_iot * G) + ''.join(str(t_iot * G_k[i]) for i in range(len(edge.iots))) + str(t_iot * B))
            iot.credential = {
                'A': A_iot, 'B': B_iot, 'C': C_iot, 'D': D_iot, 'E0': E0_iot, 'E_k': E_k_iot,
                'challenge': challenge_iot
            }
            logger.debug(f"IoT {iot.id}: Credential CRE={iot.credential}")

            # Generate tracing token (ElGamal encryption)
            k = PAIRING_GROUP.random(ZR)
            C1 = k * G
            C2 = iot.public_key + k * tracer.public_key
            iot.tracing_token = {'C1': C1, 'C2': C2}
            logger.debug(f"IoT {iot.id}: Tracing token={iot.tracing_token}")

    logger.info("Completed Join Phase")
    return {
        'edges': edges,
        'iots': iots,
        'issuer': issuer,
        'tracer': tracer
    }