import logging
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2

# Configure logging to capture all protocol steps
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spark_protocol.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize pairing group for BN254 curve (per user preference)
GROUP = PairingGroup('BN254')

# Cryptographic field and curve parameters
q = GROUP.order()  # Prime order of the cyclic group
F = ZR  # Finite field Z_q
E = G1  # Elliptic curve group G1 over F
E_tilde = G2  # Elliptic curve group G2 over extension field
G0 = GROUP.random(G1)  # Generator point in G1
G0_tilde = GROUP.random(G2)  # Generator point in G2
H = GROUP.random(G1)  # Additional generator for ZKPs
H_tilde = GROUP.random(G2)  # Additional generator for pairings

# CAN network parameters (from Table 4 of the paper)
CAN_SPEC = {
    'CAN': {'R_arb_max': 1e6, 'R_data_max': 1e6, 'max_payload': 8},
    'CAN_FD': {'R_arb_max': 1e6, 'R_data_max': 8e6, 'max_payload': 64},
    'CAN_XL': {'R_arb_max': 1e6, 'R_data_max': 20e6, 'max_payload': 2048}
}

# Network and protocol configuration
EDGE_IOT_COUNTS = [3, 4, 5, 6]  # Number of IoT devices per Edge (user-specified)
NUM_EDGE_DEVICES = 4  # Number of Zonal Gateways
CAN_TYPE = 'CAN_XL'  # Use CAN XL for high-speed communication
MAX_IOT_DEVICES = max(EDGE_IOT_COUNTS)  # Maximum IoT devices for G_k generation
BASENAME = b"spark_basename"  # Basename for attestation

# TPM simulation parameters
TPM_POLICY = {'state': 'correct'}  # Simulated TPM policy (correct state)

# Log initialization details
logger.info(
    "Configuration initialized: BN254 curve, %d Edge devices, IoT counts=%s, %s network",
    NUM_EDGE_DEVICES, EDGE_IOT_COUNTS, CAN_TYPE
)