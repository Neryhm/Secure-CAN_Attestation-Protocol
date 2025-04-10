import asyncio
import pandas as pd
from crypto.primitives import CryptoPrimitives
from entities.devices import Issuer, InternalVerifier, EdgeDevice, IoTDevice, Tracer
from phases.key_setup import KeySetup
from phases.join import JoinPhase
from phases.attestation import AttestationPhase
from phases.verification import VerificationPhase

# Global log
phase_data = []

async def run_simulation():
    print("Starting SPARK protocol simulation...\n")

    issuer = Issuer()
    verifier = InternalVerifier()
    edge_devices = [EdgeDevice(f"edge_{i+1}") for i in range(4)]
    iot_devices_per_edge = {edge.device_id: [IoTDevice(f"iot_{j+1}") for j in range(i*5, (i+1)*5)] for i, edge in enumerate(edge_devices)}
    issuer.generate_tracing_keypair()
    tracer = Tracer(issuer.tracing_keypair[0])

    print("=== Key Setup Phase ===")
    key_setup = KeySetup(num_iot_devices=20, phase_data=phase_data)
    group_elements = key_setup.run(issuer, verifier, edge_devices, iot_devices_per_edge)
    print("Key Setup finished.\n")

    print("=== Join Phase ===")
    join = JoinPhase(group_elements, phase_data=phase_data)
    join.run(issuer, edge_devices, iot_devices_per_edge)
    print("Join finished.\n")

    print("=== Attestation Phase ===")
    attestation = AttestationPhase(group_elements, phase_data=phase_data)
    signatures = await attestation.run(verifier, edge_devices)
    print("Attestation finished.\n")

    print("=== Verification Phase ===")
    verification = VerificationPhase(group_elements, phase_data=phase_data)
    results = await verification.run(verifier, edge_devices)
    print("Verification finished.\n")

    print("=== Tracing Phase ===")
    traced_ids = {}
    for edge in edge_devices:
        traced_id = tracer.trace_device(edge)
        traced_ids[edge.device_id] = traced_id
        phase_data.append({"Phase": "Tracing", "Device_ID": edge.device_id, "Traced_ID": traced_id, "Tracing_Token": str(edge.tracing_token)})
    print("Tracing finished.\n")

    print("SPARK simulation completed.")
    return results, traced_ids

async def main():
    try:
        results, traced_ids = await run_simulation()
        print("\nFinal Validation:")
        print("Verification status:", "All passed" if all(results.values()) else "Some failed")
        print("Tracing correct:", "Yes" if all(traced_ids[edge_id] == edge_id for edge_id in traced_ids) else "No")

        # Debug print
        print(f"Phase data before export (length: {len(phase_data)}):")
        for i, entry in enumerate(phase_data):
            print(f"Entry {i}: {entry}")

        # Export to Excel
        df = pd.DataFrame(phase_data)
        print(f"DataFrame shape: {df.shape}")
        print(f"DataFrame columns: {df.columns.tolist()}")
        df.to_excel("spark_simulation_log.xlsx", index=False, engine='openpyxl')
        print("Simulation data exported to 'spark_simulation_log.xlsx'.")
    except Exception as e:
        print(f"Simulation failed with error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())