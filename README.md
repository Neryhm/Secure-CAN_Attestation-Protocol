config.py: Defines the network structure (4 Edges with 3, 4, 5, 6 IoTs), cryptographic parameters (BN256 curve), and logging configuration.
crypto/ecc.py: Implements ECC operations (pairing, group operations, hash functions.
crypto/tpm_sim.py: Simulates TPM 2.0 key generation and policy enforcement.
entities/*.py: Defines classes for Edge, IoT, Issuer, Tracer, and Verifier, encapsulating their keys and behaviors.
protocols/key_setup.py: Implements the Key Setup Phase (Section 7.1).
protocols/*.py: Will contain implementations for Join, Attestation, Verification, and Tracing phases in future parts.
network/can_sim.py: Will simulate CAN network communication for network overhead analysis.
main.py: Orchestrates the protocol execution, starting with the Key Setup Phase.
requirements.txt: Lists dependencies (charm-crypto, cryptography).