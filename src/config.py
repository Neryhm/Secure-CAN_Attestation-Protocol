import logging
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spark_protocol.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Pairing group for BN254 curve
GROUP = PairingGroup('BN254')

# Field and curve parameters
q = GROUP.order()  # Prime order of the cyclic group
F = ZR  # Finite field Z_q
E = G1  # Elliptic curve over F
E_tilde = G2  # Points of E over extension field
G0 = GROUP.random(G1)  # Base point in E
G0_tilde = GROUP.random(G2)  # Base point in E_tilde

# CAN network parameters (from Table 4)
CAN_SPEC = {
    'CAN': {'R_arb_max': 1e6, 'R_data_max': 1e6, 'max_payload': 8},
    'CAN_FD': {'R_arb_max': 1e6, 'R_data_max': 8e6, 'max_payload': 64},
    'CAN_XL': {'R_arb_max': 1e6, 'R_data_max': 20e6, 'max_payload': 2048}
}

# Network configuration
EDGE_IOT_COUNTS = [3, 4, 5, 6]  # IoT devices per Edge
NUM_EDGE_DEVICES = 4  # Number of Zonal Gateways
CAN_TYPE = 'CAN_XL'  # CAN standard to use
MAX_IOT_DEVICES = max(EDGE_IOT_COUNTS)  # For generating G_k

# TPM simulation parameters
TPM_POLICY = {'state': 'correct'}  # Simulated TPM policy

logger.info("Configuration initialized with BN254 curve and %s network", CAN_TYPE)