import asyncio
import pandas as pd
from crypto.primitives import CryptoPrimitives
from entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice, Tracer
from phases.key_setup import KeySetup
from phases.join import JoinPhase
from phases.attestation import AttestationPhase
from phases.verification import VerificationPhase

phase_data = []     # Global list to store debug prints

async def run_simulation():
    """Run the full SPARK protocol simulation with detailed debug prints."""
    print("Starting SPARK protocol simulation...\n")

    # Initialize entities
    issuer = Issuer()
    verifier = InternalVerifier()

    edge1 = EdgeDevice("edge_1")
    iot1 = IoTDevice("iot_1")
    iot2 = IoTDevice("iot_2")
    iot3 = IoTDevice("iot_3")
    iot4 = IoTDevice("iot_4")
    iot5 = IoTDevice("iot_5")

    edge2 = EdgeDevice("edge_2")
    iot6 = IoTDevice("iot_6")
    iot7 = IoTDevice("iot_7")
    iot8 = IoTDevice("iot_8")
    iot9 = IoTDevice("iot_9")
    iot10 = IoTDevice("iot_10")

    edge3 = EdgeDevice("edge_3")
    iot11 = IoTDevice("iot_11")
    iot12 = IoTDevice("iot_12")
    iot13 = IoTDevice("iot_13")
    iot14 = IoTDevice("iot_14")
    iot15 = IoTDevice("iot_15")

    edge4 = EdgeDevice("edge_4")
    iot16 = IoTDevice("iot_16")
    iot17 = IoTDevice("iot_17")
    iot18 = IoTDevice("iot_18")
    iot19 = IoTDevice("iot_19")
    iot20 = IoTDevice("iot_20")

    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])
    
    edge_devices = [edge1, edge2, edge3, edge4]
    iot_devices_per_edge = {
        "edge_1": [iot1, iot2, iot3, iot4, iot5],
        "edge_2": [iot6, iot7, iot8, iot9, iot10],
        "edge_3": [iot11, iot12, iot13, iot14, iot15],
        "edge_4": [iot16, iot17, iot18, iot19, iot20]
        }
    
    # Step 1: Key Setup
    print("=== Key Setup Phase ===")
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    print("Group elements:", len(group_elements))
    print("Issuer private key:", issuer.private_key)
    print("Issuer public key:", issuer.public_key)
    print("Edge1 TPM private key:", edge1.tpm.private_key)
    print("Edge1 TPM public key:", edge1.tpm.public_key)
    print("Edge2 TPM private key:", edge2.tpm.private_key)
    print("Edge2 TPM public key:", edge2.tpm.public_key)
    print("Edge3 TPM private key:", edge3.tpm.private_key)
    print("Edge3 TPM public key:", edge3.tpm.public_key)
    print("Edge4 TPM private key:", edge4.tpm.private_key)
    print("Edge4 TPM public key:", edge4.tpm.public_key)
    print("IoT1 branch key:", iot1.branch_key)
    print("IoT2 branch key:", iot2.branch_key)
    print("IoT3 branch key:", iot3.branch_key)
    print("IoT4 branch key:", iot4.branch_key)
    print("IoT5 branch key:", iot5.branch_key)
    print("IoT6 branch key:", iot6.branch_key)
    print("IoT7 branch key:", iot7.branch_key)
    print("IoT8 branch key:", iot8.branch_key)
    print("IoT9 branch key:", iot9.branch_key)
    print("IoT10 branch key:", iot10.branch_key)
    print("IoT11 branch key:", iot11.branch_key)
    print("IoT12 branch key:", iot12.branch_key)
    print("IoT13 branch key:", iot13.branch_key)
    print("IoT14 branch key:", iot14.branch_key)
    print("IoT15 branch key:", iot15.branch_key)
    print("IoT16 branch key:", iot16.branch_key)
    print("IoT17 branch key:", iot17.branch_key)
    print("IoT18 branch key:", iot18.branch_key)
    print("IoT19 branch key:", iot19.branch_key)
    print("IoT20 branch key:", iot20.branch_key)

    print("Key Setup finished.\n")
    
    # Step 2: Join
    print("=== Join Phase ===")
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    print("Edge1 credential:", edge1.credential)
    print("Edge1 tracing token:", edge1.tracing_token)
    print("Edge2 credential:", edge2.credential)
    print("Edge2 tracing token:", edge2.tracing_token)
    print("Edge3 credential:", edge3.credential)
    print("Edge3 tracing token:", edge3.tracing_token)
    print("Edge4 credential:", edge4.credential)
    print("Edge4 tracing token:", edge4.tracing_token)

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