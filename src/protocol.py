from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
import logging
from config import GROUP, G0, EDGE_IOT_COUNTS, MAX_IOT_DEVICES
from entities import EdgeDevice, Issuer, Verifier, Tracer
from crypto_utils import CryptoUtils
from network import CANNetwork

logger = logging.getLogger(__name__)

class SPARKProtocol:
    def __init__(self):
        self.issuer = Issuer()
        self.tracer = Tracer()
        self.G_k = [GROUP.random(G1) for _ in range(MAX_IOT_DEVICES)]
        self.G = GROUP.random(G1)
        self.edges = [EdgeDevice(i + 1, num_iot, self.G_k[:num_iot]) for i, num_iot in enumerate(EDGE_IOT_COUNTS)]
        self.internal_verifier = Verifier(is_internal=True)
        self.external_verifier = Verifier(is_internal=False)
        logger.info("SPARK protocol initialized with %d Edge devices: %s IoT devices", len(self.edges), EDGE_IOT_COUNTS)

    def key_setup_phase(self):
        """Execute Key Setup Phase."""
        for edge in self.edges:
            for i, iot in enumerate(edge.iot_devices):
                iot.public_key = iot.private_key * self.G_k[i]
            edge.tpm.public_key = edge.tpm.private_key * G0
        logger.info("Key Setup Phase completed")

    def join_phase(self):
        """Execute Join Phase."""
        for edge in self.edges:
            self.issuer.issue_credential(edge)
            tk = GROUP.random(ZR)
            self.tracer.records[tk] = edge.tpm.public_key
            edge.tpm.trace_key = tk
        logger.info("Join Phase completed")

    def attestation_phase(self, edge: EdgeDevice, message: bytes) -> dict:
        """Execute Attestation Phase."""
        a = GROUP.random(ZR)
        A_prime = a * edge.credential['A']
        B_prime = a * edge.credential['B']
        C_prime = a * edge.credential['C']
        D_prime = a * edge.credential['D']
        E0_prime = a * edge.credential['E0']
        E_k_prime = [a * ek for ek in edge.credential['E_k']]

        bsn_T = b"basename"
        J_T = CryptoUtils.hash_to_G1(bsn_T)
        omega_0, R0, K0 = edge.tpm.commit(bsn_T)
        R_sum = R0
        omega_k_list = []
        for iot in edge.iot_devices:
            omega_k, R_k = iot.commit()
            R_sum += R_k
            omega_k_list.append(omega_k)

        r = GROUP.random(ZR)
        omega_r = GROUP.random(ZR)
        enc_tk = CryptoUtils.elgamal_encrypt(self.tracer.public_key, edge.tpm.trace_key)
        c_data = (
            A_prime.serialize() + B_prime.serialize() + C_prime.serialize() +
            D_prime.serialize() + E0_prime.serialize() +
            b''.join(ek.serialize() for ek in E_k_prime) +
            R_sum.serialize() + message + str(0).encode() +
            (omega_r * G0).serialize() + (omega_r * self.tracer.public_key + K0).serialize()
        )
        c = CryptoUtils.hash_to_Zq(c_data)
        s_r = omega_r + c * r

        k_commit = GROUP.random(ZR)
        s0 = edge.tpm.generate_signature(c_data, k_commit)
        s_k = [iot.sign(omega_k, c) for iot, omega_k in zip(edge.iot_devices, omega_k_list)]

        signature = {
            'A_prime': A_prime, 'B_prime': B_prime, 'C_prime': C_prime,
            'D_prime': D_prime, 'E0_prime': E0_prime, 'E_k_prime': E_k_prime,
            's0': s0, 's_k': s_k, 'c': c, 'k': 0, 's_r': s_r, 'ENC(TK)': enc_tk
        }
        CANNetwork.transmit_message(c_data)
        logger.info("Attestation Phase completed for Edge %d", edge.id)
        return signature

    def verification_phase(self, signature: dict, message: bytes, edge: EdgeDevice) -> bool:
        """Execute Verification Phase."""
        result = self.internal_verifier.verify_signature(signature, self.issuer.public_key, message, edge)
        logger.info("Verification Phase result for Edge %d: %s", edge.id, result)
        return result

    def tracing_phase(self, signature: dict) -> G1:
        """Execute Tracing Phase."""
        pk = self.tracer.trace(signature)
        logger.info("Tracing Phase completed")
        return pk