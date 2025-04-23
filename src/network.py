import logging
from config import CAN_SPEC, CAN_TYPE

logger = logging.getLogger(__name__)

class CANNetwork:
    @staticmethod
    def compute_transmission_time(payload_bytes: int, can_type: str = CAN_TYPE) -> float:
        """Compute worst-case transmission time in seconds."""
        spec = CAN_SPEC[can_type]
        R_arb = spec['R_arb_max']
        R_data = spec['R_data_max']
        tau_arb = 1 / R_arb
        tau_data = 1 / R_data
        p = payload_bytes

        if can_type == 'CAN':
            l_m = (55 + 10 * p) * tau_data
        elif can_type == 'CAN_FD':
            l_m = 32 * tau_arb + (28 + 5 * ((p - 16) // 64 if p > 16 else 0) + 10 * p) * tau_data
        else:  # CAN_XL
            l_m = 37 * tau_arb + (119 + ((109 + 8 * p) // 10) + 8 * p) * tau_data

        logger.debug("Transmission time for %d bytes on %s: %.6f s", p, can_type, l_m)
        return l_m

    @staticmethod
    def transmit_message(message: bytes) -> float:
        """Simulate message transmission and return delay."""
        payload_size = len(message)
        delay = CANNetwork.compute_transmission_time(payload_size)
        logger.info("Transmitted message of %d bytes with delay %.6f s", payload_size, delay)
        return delay