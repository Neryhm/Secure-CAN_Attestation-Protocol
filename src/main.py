import asyncio
from crypto.primitives import CryptoPrimitives
from entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice, Tracer
from phases.key_setup import KeySetup
from phases.join import JoinPhase
from phases.attestation import AttestationPhase
from phases.verification import VerificationPhase

async def run_simulation():
    """Run the full SPARK protocol simulation with detailed debug prints."""
    print("Starting SPARK protocol simulation...\n")

    # Initialize entities
    issuer = Issuer()
    verifier = InternalVerifier()
    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])
    
    edge_devices = [edge1]
    iot_devices_per_edge = {"edge_1": [iot1, iot2]}
    
    # Step 1: Key Setup
    print("=== Key Setup Phase ===")
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    print("Group elements:", group_elements)
    print("Issuer private key:", issuer.private_key)
    print("Issuer public key:", issuer.public_key)
    print("Edge TPM private key:", edge1.tpm.private_key)
    print("Edge TPM public key:", edge1.tpm.public_key)
    print("IoT1 branch key:", iot1.branch_key)
    print("IoT2 branch key:", iot2.branch_key)
    print("Key Setup finished.\n")
    
    # Step 2: Join
    print("=== Join Phase ===")
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    print("Edge credential:", edge1.credential)
    print("Edge tracing token:", edge1.tracing_token)
    print("Join finished.\n")
    
    # Step 3: Attestation (Edge-only for simplicity)
    print("=== Attestation Phase ===")
    attestation = AttestationPhase(group_elements)
    signatures = await attestation.run(verifier, edge_devices)
    s, c, R = signatures["edge_1"]
    print("Edge signature components:")
    print("  s (signature scalar):", s)
    print("  c (challenge):", c)
    print("  R (commitment point):", R)
    print("Attestation finished.\n")
    
    # Step 4: Verification
    print("=== Verification Phase ===")
    verification = VerificationPhase(group_elements)
    results = await verification.run(verifier, edge_devices)
    print("Verification results for all devices:", results)
    print("Verification finished.\n")
    
    # Step 5: Tracing
    print("=== Tracing Phase ===")
    traced_id = tracer.trace_device(edge1)
    print("Decrypted tracing token:", edge1.tracing_token)
    print("Traced device ID:", traced_id)
    print("Tracing finished.\n")
    
    print("SPARK simulation completed.")
    return results, traced_id

async def main():
    """Main entry point for the simulation."""
    try:
        results, traced_id = await run_simulation()
        print("\nFinal Validation:")
        print("Verification status:", "All passed" if all(results.values()) else "Some failed")
        print("Tracing correct:", "Yes" if traced_id == "edge_1" else "No")
        print("Simulation finished successfully.")
    except Exception as e:
        print(f"Simulation failed with error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())