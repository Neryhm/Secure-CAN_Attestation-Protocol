import logging
from src.config import EDGES, IOT_DEVICES
from src.protocols.key_setup import key_setup_phase
from src.protocols.join import join_phase

logger = logging.getLogger(__name__)

def main():
    logger.info("Starting SPARK Protocol")
    key_setup_result = key_setup_phase(EDGES, IOT_DEVICES, None, None, None, None)
    join_result = join_phase(key_setup_result)
    logger.info("SPARK Part 1 & 2: Key Setup and Join Phases completed")
    return join_result

if __name__ == "__main__":
    main()