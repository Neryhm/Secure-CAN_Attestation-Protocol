import logging
import sys
from io import StringIO
from protocol import SPARKProtocol
from config import logger, EDGE_IOT_COUNTS

class OutputLogger:
    def __init__(self, filename: str):
        """Redirect console output to file."""
        self.file = open(filename, 'w')
        self.stdout = sys.stdout
        sys.stdout = self

    def write(self, message: str):
        self.file.write(message)
        self.stdout.write(message)

    def flush(self):
        self.file.flush()
        self.stdout.flush()

    def close(self):
        sys.stdout = self.stdout
        self.file.close()

def main():
    """Execute full SPARK protocol."""
    output_logger = OutputLogger('spark_output.txt')
    logger.info("Starting SPARK protocol execution")

    # Initialize protocol
    protocol = SPARKProtocol()

    # Run Key Setup Phase
    logger.info("Executing Key Setup Phase")
    protocol.key_setup_phase()

    # Run Join Phase
    logger.info("Executing Join Phase")
    protocol.join_phase()

    # Test attestation, verification, and tracing for each Edge
    for i, edge in enumerate(protocol.edges):
        logger.info("Testing Edge %d with %d IoT devices", edge.id, EDGE_IOT_COUNTS[i])
        message = f"Test attestation for Edge {edge.id}".encode()
        
        # Attestation Phase
        logger.info("Edge %d: Starting Attestation Phase")
        signature = protocol.attestation_phase(edge, message)
        
        # Verification Phase
        logger.info("Edge %d: Starting Verification Phase")
        is_valid = protocol.verification_phase(signature, message, edge)
        logger.info("Edge %d: Signature valid=%s", edge.id, is_valid)

        # Tracing Phase
        logger.info("Edge %d: Starting Tracing Phase")
        traced_pk = protocol.tracing_phase(signature)
        logger.info("Edge %d: Traced public key=%s", edge.id, traced_pk)

    logger.info("SPARK protocol execution completed")
    output_logger.close()

if __name__ == "__main__":
    main()