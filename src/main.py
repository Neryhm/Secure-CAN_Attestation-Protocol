# spark_simulation/src/main.py

import asyncio
from crypto.primitives import CryptoPrimitives
from entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice, Tracer
from phases.key_setup import KeySetup
from phases.join import JoinPhase
from phases.attestation import AttestationPhase
from phases.verification import VerificationPhase

async def run_simulation():
    """Run the full SPARK protocol simulation."""
    print("Starting SPARK protocol simulation...")

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
    
    # Step 5: Key Setup
    print("Running Key Setup phase...")
    key_setup = KeySetup(num_iot_devices=2)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    print("Key Setup complete. Group elements generated:", len(group_elements))
    
    # Step 6: Join
    print("Running Join phase...")
    join = JoinPhase(group_elements)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    print("Join complete. Devices enrolled:", len(edge_devices) + sum(len(iots) for iots in iot_devices_per_edge.values()))
    
    # Step 7: Attestation (with network simulation)
    print("Running Attestation phase...")
    attestation = AttestationPhase(group_elements)
    signatures = await attestation.run(verifier, edge_devices)
    print("Attestation complete. Signatures generated:", len(signatures))
    
    # Step 8: Verification
    print("Running Verification phase...")
    verification = VerificationPhase(group_elements)
    results = await verification.run(verifier, edge_devices)
    print("Verification complete. Results:", results)
    
    # Step 11: Tracing
    print("Running Tracing...")
    traced_id = tracer.trace_device(edge1)
    print("Tracing complete. Identified device:", traced_id)
    
    # Summary
    print("SPARK simulation completed successfully.")
    return results, traced_id

async def main():
    """Main entry point for the simulation."""
    try:
        results, traced_id = await run_simulation()
        assert all(results.values()), "Verification failed for some devices"
        assert traced_id == "edge_1", "Tracing identified wrong device"
        print("All phases executed correctly.")
    except Exception as e:
        print(f"Simulation failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())