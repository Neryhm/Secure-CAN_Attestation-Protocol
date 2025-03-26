import asyncio

class NetworkSimulator:
    """Simulates CAN-like network communication with delays."""

    def __init__(self, bandwidth=1_000_000):  # 1 Mbit/s default
        self.bandwidth = bandwidth  # bits per second

    async def send_message(self, sender_id, receiver_id, message_size_bytes, data):
        """Simulate sending a message with delay based on size and bandwidth."""
        # Calculate delay: time = (message size in bits) / bandwidth
        message_size_bits = message_size_bytes * 8
        delay_seconds = message_size_bits / self.bandwidth  # e.g., 64 bytes = 0.512 ms
        
        # Simulate transmission delay
        await asyncio.sleep(delay_seconds)
        print(f"Message from {sender_id} to {receiver_id}: {message_size_bytes} bytes, "
              f"delay {delay_seconds*1000:.3f} ms")
        return data

async def test_network():
    """Test the network simulation."""
    net = NetworkSimulator()
    
    # Simulate a 64-byte message (common CAN frame size)
    result = await net.send_message("iot_1", "edge_1", 64, "test_data")
    assert result == "test_data", "Message data corrupted"
    print("Network simulation test passed.")

if __name__ == "__main__":
    asyncio.run(test_network())