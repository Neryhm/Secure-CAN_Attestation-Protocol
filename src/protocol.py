from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
import logging
from config import GROUP, G0, EDGE_IOT_COUNTS, MAX_IOT_DEVICES, BASENAME
from entities import EdgeDevice, Issuer, Verifier, Tracer
from crypto_utils import CryptoUtils
from network import CANNetwork

logger = logging.getLogger(__name__)

class SPARKProtocol:
    def __init__(self):
        """Initialize SPARK protocol with all entities."""
        self.issuer = Issuer()
        self.tracer = Tracer()
        self.G_k = [GROUP.random(G1) for _ in range(MAX_IOT_DEVICES)]  # Base points for IoT devices
        self.G = GROUP.random(G1)  # Additional base point
        self.edges = [EdgeDevice(i + 1, num_iot, self.G_k[:num_iot])
                      for i, num_iot in enumerate(EDGE_IOT_COUNTS)]
        self.internal_verifier = Verifier(is_internal=True)
        self.external_verifier = Verifier(is_internal=False)
        logger.info("SPARK protocol initialized: edges=%d, iot_counts=%s",
                    len(self.edges), EDGE_IOT_COUNTS)

    def key_setup_phase(self):
        """Key Setup Phase: Generate keys for all devices."""
        logger.info("Starting Key Setup Phase")
        for edge in self.edges:
            # Set TPM public key
            edge.tpm.public_key = edge.tpm.private_key * G0
            logger.debug("Edge %d TPM public key: %s", edge.id, edge.tpm.public_key)
            # Set IoT device public keys
            for i, iot in enumerate(edge.iot_devices):
                iot.public_key = iot.private_key * self.G_k[i]
                logger.debug("Edge %d, IoT %d public key: %s",
                             edge.id, iot.id, iot.public_key)
        logger.info("Key Setup Phase completed")

    def join_phase(self):
        """Join Phase: Issue CL credentials and trace keys."""
        logger.info("Starting Join Phase")
        for edge in self.edges:
            # Issuer checks eligibility and issues credential
            self.issuer.issue_credential(edge)
            # Assign trace key
            tk = GROUP.random(ZR)
            self.tracer.records[tk] = edge.tpm.public_key
            edge.tpm.trace_key = tk
            logger.debug("Edge %d trace key: %s", edge.id, tk)
        logger.info("Join Phase completed")

    def attestation_phase(self, edge: EdgeDevice, message: bytes) -> dict:
        """Attestation Phase: Generate group signature."""
        logger.info("Starting Attestation Phase for Edge %d", edge.id)
        
        # Step 1: Randomize CL credential
        a = GROUP.random(ZR)
        A_prime = a * edge.credential['A']
        B_prime = a * edge.credential['B']
        C_prime = a * edge.credential['C']
        D_prime = a * edge.credential['D']
        E0_prime = a * edge.credential['E0']
        E_k_prime = [a * ek for ek in edge.credential['E_k']]
        logger.debug("Edge %d randomized credential: A_prime=%s, B_prime=%s, C_prime=%s, D_prime=%s, E0_prime=%s",
                     edge.id, A_prime, B_prime, C_prime, D_prime, E0_prime)

        # Step 2: TPM commitment
        omega_0, R0, K0 = edge.tpm.commit(BASENAME)
        R_sum = R0
        logger.debug("Edge %d TPM commit: omega_0=%s, R0=%s, K0=%s",
                     edge.id, omega_0, R0, K0)

        # Step 3: IoT device commitments
        omega_k_list = []
        for iot in edge.iot_devices:
            omega_k, R_k = iot.commit()
            R_sum += R_k
            omega_k_list.append(omega_k)
            logger.debug("Edge %d, IoT %d commit: omega_k=%s, R_k=%s",
                         edge.id, iot.id, omega_k, R_k)

        # Step 4: Generate ZKP for tracing
        r = GROUP.random(ZR)
        omega_r, T_r = CryptoUtils.generate_zkp_commitment(r)
        enc_tk = CryptoUtils.elgamal_encrypt(self.tracer.public_key, edge.tpm.trace_key)
        logger.debug("Edge %d ZKP: r=%s, T_r=%s, enc_tk=%s",
                     edge.id, r, T_r, enc_tk)

        # Step 5: Compute challenge
        c_data = (
            A_prime.serialize() + B_prime.serialize() + C_prime.serialize() +
            D_prime.serialize() + E0_prime.serialize() +
            b''.join(ek.serialize() for ek in E_k_prime) +
            R_sum.serialize() + message + b'0' +
            T_r.serialize() + (omega_r * self.tracer.public_key + K0).serialize()
        )
        c = CryptoUtils.hash_to_Zq(c_data)
        logger.debug("Edge %d challenge: c=%s", edge.id, c)

        # Step 6: Generate ZKP responses
        s_r = CryptoUtils.generate_zkp_response(r, omega_r, c)
        k_commit = GROUP.random(ZR)
        s0 = edge.tpm.generate_signature(c_data, k_commit)
        s_k = [iot.sign(omega_k, c) for iot, omega_k in zip(edge.iot_devices, omega_k_list)]
        logger.debug("Edge %d ZKP responses: s_r=%s, s0=%s, s_k=%s",
                     edge.id, s_r, s0, s_k)

        # Step 7: Construct signature
        signature = {
            'A_prime': A_prime, 'B_prime': B_prime, 'C_prime': C_prime,
            'D_prime': D_prime, 'E0_prime': E0_prime, 'E_k_prime': E_k_prime,
            's0': s0, 's_k': s_k, 'c': c, 'k': 0, 's_r': s_r, 'ENC(TK)': enc_tk
        }
        logger.debug("Edge %d signature: %s", edge.id, signature)

        # Step 8: Transmit over CAN network
        CANNetwork.transmit_message(c_data)
        logger.info("Attestation Phase completed for Edge %d", edge.id)
        return signature

    def verification_phase(self, signature: dict, message: bytes, edge: EdgeDevice) -> bool:
        """Verification Phase: Verify group signature."""
        logger.info("Starting Verification Phase for Edge %d", edge.id)
        result = self.internal_verifier.verify_signature(
            signature, self.issuer.public_key, message, edge
        )
        logger.info("Verification Phase result for Edge %d: %s", edge.id, result)
        return result

    def tracing_phase(self, signature: dict) -> G1:
        """Tracing Phase: Identify device from signature."""
        logger.info("Starting Tracing Phase")
        pk = self.tracer.trace(signature)
        logger.info("Tracing Phase completed: pk=%s", pk)
        return pk