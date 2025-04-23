import logging
from charm.toolbox.pairinggroup import ZR
from src.config import PAIRING_GROUP
from src.crypto.ecc import H, H1, generate_schnorr_proof

logger = logging.getLogger(__name__)

def join_phase(key_setup_result):
    """Implement Join Phase (Section 7.2)."""
    logger.info("Starting Join Phase")

    # Extract key setup results
    G = key_setup_result['G']
    G_tilde = key_setup_result['G_tilde']
    issuer = key_setup_result['issuer']
    tracer = key_setup_result['tracer']
    edges = key_setup_result['edges']
    iots = key_setup_result['iots']
    x = issuer.private_key['x']  # Issuer private key for CL signature

    # Process each Edge device
    for edge in edges:
        logger.info(f"Processing Edge {edge.id}")

        # Simulate TPM signature on PK
        tpm_signature = generate_schnorr_proof(edge.tpm_key, edge.public_key, G)
        logger.debug(f"Edge {edge.id}: TPM signature={tpm_signature}")

        # Eligibility check (mocked)
        is_eligible = edge.tpm_policy['state'] == 'correct'
        logger.debug(f"Edge {edge.id}: Eligibility check={is_eligible}")
        assert is_eligible, f"Edge {edge.id} not eligible"

        # Generate branch key
        nonce = PAIRING_GROUP.random(ZR)
        B = H(edge.tpm_policy, nonce)  # Branch key B
        edge.branch_key = B
        logger.debug(f"Edge {edge.id}: Branch key B={B}, Nonce={nonce}")

        # Generate branch credential (CL signature)
        e = PAIRING_GROUP.random(ZR)  # Random scalar (simplified, not prime)
        s = PAIRING_GROUP.random(ZR)  # Random scalar
        H1_B = H1(str(B))
        logger.debug(f"Edge {edge.id}: H1(B)={H1_B}")
        # Compute A = (G + PK + H1(B)^s)^(1/(e+x)) using modular inverse
        denominator = e + x
        if denominator == PAIRING_GROUP.init(ZR, 0):
            logger.error(f"Edge {edge.id}: Denominator e+x is zero, regenerating e")
            e = PAIRING_GROUP.random(ZR)  # Regenerate e to avoid zero denominator
            denominator = e + x
        inv_denominator = 1 / denominator  # Compute modular inverse in ZR
        logger.debug(f"Edge {edge.id}: e={e}, x={x}, e+x={denominator}, inv(e+x)={inv_denominator}")
        base = G + edge.public_key + H1_B * s
        A = base * inv_denominator  # A = (G + PK + H1(B)^s)^(1/(e+x))
        edge.credential = {'A': A, 'e': e, 's': s, 'tpm_signature': tpm_signature}
        logger.debug(f"Edge {edge.id}: Credential CRE={edge.credential}")

        # Process IoT devices under this Edge
        for iot_id in edge.iots:
            iot = iots[iot_id]  # Use iot_id directly
            logger.info(f"Processing IoT {iot.id}")

            # Generate IoT credential (CL signature)
            e_iot = PAIRING_GROUP.random(ZR)
            s_iot = PAIRING_GROUP.random(ZR)
            denominator_iot = e_iot + x
            if denominator_iot == PAIRING_GROUP.init(ZR, 0):
                logger.error(f"IoT {iot.id}: Denominator e+x is zero, regenerating e_iot")
                e_iot = PAIRING_GROUP.random(ZR)
                denominator_iot = e_iot + x
            inv_denominator_iot = 1 / denominator_iot  # Compute modular inverse in ZR
            logger.debug(f"IoT {iot.id}: e_iot={e_iot}, x={x}, e_iot+x={denominator_iot}, inv(e_iot+x)={inv_denominator_iot}")
            base_iot = G + iot.public_key + H1_B * s_iot
            A_iot = base_iot * inv_denominator_iot  # A = (G + X_k + H1(B)^s)^(1/(e+x))
            iot.credential = {'A': A_iot, 'e': e_iot, 's': s_iot}
            logger.debug(f"IoT {iot.id}: Credential CRE={iot.credential}")

            # Generate tracing token (ElGamal encryption)
            k = PAIRING_GROUP.random(ZR)  # Encryption randomness
            C1 = k * G  # First part of ciphertext
            C2 = iot.public_key + k * tracer.public_key  # Second part
            iot.tracing_token = {'C1': C1, 'C2': C2}
            logger.debug(f"IoT {iot.id}: Tracing token={iot.tracing_token}")

    logger.info("Completed Join Phase")
    return {
        'edges': edges,
        'iots': iots,
        'issuer': issuer,
        'tracer': tracer
    }