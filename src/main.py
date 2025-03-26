import sys
import charm.core.engine.util
import cryptography
import asyncio
from crypto.primitives import CryptoPrimitives
from entities.tpm_emulator import TPMEmulator
from entities.devices import Issuer, EdgeDevice, InternalVerifier, Tracer, test_entities
from phases.key_setup import test_key_setup
from phases.join import test_join_phase
from phases.attestation import test_attestation_phase
from phases.verification import test_verification_phase

async def test_tracing():
    """Test the tracing functionality."""
    issuer = Issuer()
    edge = EdgeDevice("edge_1")
    verifier = InternalVerifier()
    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])
    
    key_setup = KeySetup()
    group_elements = key_setup.run(issuer, verifier, [edge], {"edge_1": []})
    join = JoinPhase(group_elements)
    join.run(issuer, [edge], {"edge_1": []})
    
    traced_id = tracer.trace_device(edge)
    assert traced_id == "edge_1", "Tracing failed"
    print("Tracing successful:", traced_id)

async def check_environment():
    """Verify that required libraries are installed."""
    try:
        # Check Charm-Crypto
        from charm.toolbox.pairinggroup import PairingGroup, G1
        group = PairingGroup('BN254')  # BN_P256-like curve
        print("Charm-Crypto is installed and functional.")
    except ImportError:
        print("Error: Charm-Crypto is not installed. Install with 'pip install charm-crypto'.")
        sys.exit(1)

    try:
        # Check Cryptography
        from cryptography.hazmat.primitives import hashes
        digest = hashes.Hash(hashes.SHA256())
        print("Cryptography library is installed and functional.")
    except ImportError:
        print("Error: Cryptography is not installed. Install with 'pip install cryptography'.")
        sys.exit(1)

    # Check asyncio (built-in, should always work with Python 3.8+)
    async def test_async():
        await asyncio.sleep(0.1)
        return "Asyncio is functional."
    
    result = asyncio.run(test_async())
    print(result)

    # Check for CryptoPrimitives
    try:
        crypto = CryptoPrimitives()
        test_primitives()
        print("Cryptographic primitives are functional.")
    except Exception as e:
        print(f"Error in cryptographic primitives: {e}")
        sys.exit(1)

    # Check TPM Emulator
    try:
        tpm = TPMEmulator()
        tpm.initialize()
        test_tpm_emulator()
        print("TPM emulator is functional.")
    except Exception as e:
        print(f"Error in TPM emulator: {e}")
        sys.exit(1)

    # Check Entities
    try:
        test_entities()
        print("Entity classes are functional.")
    except Exception as e:
        print(f"Error in entity classes: {e}")
        sys.exit(1)

    # Check Key Setup
    try:
        test_key_setup()
        print("Key Setup phase is functional.")
    except Exception as e:
        print(f"Error in Key Setup phase: {e}")
        sys.exit(1)

    # Check Join Phase
    try:
        test_join_phase()
        print("Join phase is functional.")
    except Exception as e:
        print(f"Error in Join phase: {e}")
        sys.exit(1)

    # Check Attestation Phase
    try:
        test_attestation_phase()
        print("Attestation phase is functional.")
    except Exception as e:
        print(f"Error in Attestation phase: {e}")
        sys.exit(1)

    # Check Verification Phase
    try:
        test_verification_phase()
        print("Verification phase is functional.")
    except Exception as e:
        print(f"Error in Verification phase: {e}")
        sys.exit(1)

    # Check Tracing
    try:
        await test_tracing()
        print("Tracing functionality is operational.")
    except Exception as e:
        print(f"Error in tracing: {e}")
        sys.exit(1)

def main():
    print("Setting up SPARK simulation environment...")
    check_environment()
    print("Environment setup complete. Ready to implement SPARK protocol.")

if __name__ == "__main__":
    asyncio.run(main())