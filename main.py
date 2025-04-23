import logging
from src.config import EDGES, IOT_DEVICES
from src.protocols.key_setup import key_setup_phase

logger = logging.getLogger(__name__)

def main():
    logger.info("Starting SPARK Protocol")
    result = key_setup_phase(EDGES, IOT_DEVICES, None, None, None, None)
    logger.info("SPARK Part 1: Setup and Key Setup Phase completed")
    return result

if __name__ == "__main__":
    main()