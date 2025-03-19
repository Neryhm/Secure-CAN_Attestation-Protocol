import sys
import charm.core.engine.util
import cryptography
import asyncio
from crypto.primitives import CryptoPrimitives
from crypto.primitives import test_primitives
from entities.tpm_emulator import TPMEmulator
from entities.tpm_emulator import test_tpm_emulator
from entities.devices import test_entities
from phases.key_setup import test_key_setup

def check_environment():
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

def main():
    print("Setting up SPARK simulation environment...")
    check_environment()
    print("Environment setup complete. Ready to implement SPARK protocol.")

if __name__ == "__main__":
    main()