import logging
from config import CAN_SPEC, CAN_TYPE

logger = logging.getLogger(__name__)

class CANNetwork:
    @staticmethod
    def compute_transmission_time(payload_bytes: int, can_type: str = CAN_TYPE) -> float:
        """Compute worst-case CAN transmission time (seconds) per Table 4."""
        if payload_bytes > CAN_SPEC[can_type]['max_payload']:
            logger.error("Payload size %d exceeds %s max payload %d",
                         payload_bytes, can_type, CAN_SPEC[can_type]['max_payload'])
            raise ValueError("Payload too large")
        
        spec = CAN_SPEC[can_type]
        R_arb = spec['R_arb_max']  # Arbitration bit rate
        R_data = spec['R_data_max']  # Data bit rate
        tau_arb = 1 / R_arb  # Arbitration bit time
        tau_data = 1 / R_data  # Data bit time
        p = payload_bytes

        # Compute frame length (l_m) including worst-case bit stuffing
        if can_type == 'CAN':
            l_m = (55 + 10 * p) * tau_data  # Standard CAN frame
        elif can_type == 'CAN_FD':
            l_m = 32 * tau_arb + (28 + 5 * ((p - 16) // 64 if p > 16 else 0) + 10 * p) * tau_data
        else:  # CAN_XL
            l_m = 37 * tau_arb + (119 + ((109 + 8 * p) // 10) + 8 * p) * tau_data

        logger.debug("Transmission time: can_type=%s, payload=%d, l_m=%.6f s",
                     can_type, p, l_m)
        return l_m

    @staticmethod
    def transmit_message(message: bytes) -> float:
        """Simulate CAN message transmission and return delay."""
        payload_size = len(message)
        try:
            delay = CANNetwork.compute_transmission_time(payload_size)
            logger.info("Transmitted message: size=%d bytes, delay=%.6f s",
                        payload_size, delay)
            return delay
        except ValueError as e:
            logger.error("Transmission failed: %s", str(e))
            raise