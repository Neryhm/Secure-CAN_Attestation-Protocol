import asyncio

# Global log
phase_data = []

class NetworkSimulator:
    def __init__(self, bandwidth=1_000_000):
        self.bandwidth = bandwidth

    async def send_message(self, sender_id, receiver_id, message_size_bytes, data):
        message_size_bits = message_size_bytes * 8
        delay_seconds = message_size_bits / self.bandwidth
        await asyncio.sleep(delay_seconds)
        phase_data.append({
            "Phase": "Network_Send",
            "Sender": sender_id,
            "Receiver": receiver_id,
            "Size_Bytes": message_size_bytes,
            "Delay_ms": delay_seconds * 1000,
            "Data": str(data)
        })
        return data

async def test_network():
    net = NetworkSimulator()
    result = await net.send_message("iot_1", "edge_1", 64, "test_data")
    assert result == "test_data"
    print("Network simulation test passed.")

if __name__ == "__main__":
    asyncio.run(test_network())