import logging
from charm.toolbox.pairinggroup import PairingGroup

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='spark_protocol.log',
    filemode='w'
)
logger = logging.getLogger(__name__)
logger.info("Logging configured")

# Cryptographic parameters
PAIRING_GROUP = PairingGroup('BN254')
logger.info("Pairing group initialized: BN254")

# Network structure
EDGES = [
    {'id': 'Edge_1', 'iots': ['D_1', 'D_2', 'D_3'], 'tpm_key': None, 'public_key': None, 'tpm_policy': None},
    {'id': 'Edge_2', 'iots': ['D_1', 'D_2', 'D_3', 'D_4'], 'tpm_key': None, 'public_key': None, 'tpm_policy': None},
    {'id': 'Edge_3', 'iots': ['D_1', 'D_2', 'D_3', 'D_4', 'D_5'], 'tpm_key': None, 'public_key': None, 'tpm_policy': None},
    {'id': 'Edge_4', 'iots': ['D_1', 'D_2', 'D_3', 'D_4', 'D_5', 'D_6'], 'tpm_key': None, 'public_key': None, 'tpm_policy': None}
]
logger.info(f"Defined network with {len(EDGES)} Edge devices: {[edge['id'] for edge in EDGES]}")

# Initialize IoT devices
IOT_DEVICES = {}
for edge in EDGES:
    for iot_id in edge['iots']:
        IOT_DEVICES[f"{edge['id']}_{iot_id}"] = {'private_key': None, 'public_key': None, 'proof': None}
logger.info(f"Initialized {len(IOT_DEVICES)} IoT devices")