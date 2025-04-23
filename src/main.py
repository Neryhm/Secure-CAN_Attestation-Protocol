import logging
import sys
from io import StringIO
from protocol import SPARKProtocol
from config import logger, EDGE_IOT_COUNTS

class OutputLogger:
    def __init__(self, filename: str):
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
    output_logger = OutputLogger('spark_output.txt')
    logger.info("Starting SPARK protocol execution")

    protocol = SPARKProtocol()
    protocol.key_setup_phase()
    protocol.join_phase()

    for i, edge in enumerate(protocol.edges):
        logger.info("Testing Edge %d with %d IoT devices", edge.id, EDGE_IOT_COUNTS[i])
        message = f"Test attestation for Edge {edge.id}".encode()
        signature = protocol.attestation_phase(edge, message)
        is_valid = protocol.verification_phase(signature, message, edge)
        logger.info("Signature valid for Edge %d: %s", edge.id, is_valid)
        traced_pk = protocol.tracing_phase(signature)
        logger.info("Traced public key for Edge %d: %s", edge.id, traced_pk)

    logger.info("SPARK protocol execution completed")
    output_logger.close()

if __name__ == "__main__":
    main()