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

    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    
    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])
    



    # Step 1: Key Setup
    print("=== Key Setup Phase ===")
    key_setup = KeySetup(num_iot_devices=20)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    print("Group elements:", len(group_elements))
    print("Issuer private key:", issuer.private_key)
    print("Issuer public key:", issuer.public_key)

    print("Key Setup finished.\n")
    
    # Step 2: Join
    print("=== Join Phase ===")
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)

    print("Join finished.\n")
    
    # Step 3: Attestation (Edge-only for simplicity)
    print("=== Attestation Phase ===")
    attestation = AttestationPhase(group_elements)
    signatures = await attestation.run(verifier, edge_devices)
    s, c, R = signatures["edge_devices[0]"]
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
    traced_ids = {}
    for edge in edge_devices:
        traced_id = tracer.trace_device(edge)
        traced_ids[edge.device_id] = traced_id
        phase_data.append({"Phase": "Tracing", "Device_ID": edge.device_id, "Traced_ID": traced_id, "Tracing_Token": str(edge.tracing_token)})
    print("Tracing finished.\n")
    
    print("SPARK simulation completed-----------------------")
    return results, traced_ids

async def main():
    """Main entry point for the simulation."""
    try:
        results, traced_ids = await run_simulation()
        print("\nFinal Validation:")
        print("Verification status:", "All passed" if all(results.values()) else "Some failed")
        print("Tracing correct:", "Yes" if all(traced_ids[edge_id] == edge_id for edge_id in traced_ids) else "No")
        print("Simulation finished successfully.")

        # Export simulation data to Excel
        print("Exporting simulation data to Excel...")
        phase_data.append({"Phase": "Final_Results", "Verification_Status": str(results), "Tracing_Status": str(traced_ids)})
        # Convert to DataFrame and save to Excel
        df = pd.DataFrame(phase_data)
        df.to_excel("spark_simulation_log.xlsx", index=False, engine='openpyxl')
        print("Simulation data exported to 'spark_simulation_log.xlsx'.")
    except Exception as e:
        print(f"Simulation failed with error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())