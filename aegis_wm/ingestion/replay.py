"""Deterministic timestamp-respecting replay engine for PCAPs and flow telemetry."""

import time
from pathlib import Path
from typing import Callable, Generator, List, Optional
from aegis_wm.common.logger import logger
from aegis_wm.schemas.flow import BidirectionalFlow


class TelemetryReplayEngine:
    """Replays flow records respecting original inter-event timestamps at configurable speed."""

    def __init__(self, speed_multiplier: float = 1.0):
        """
        speed_multiplier: 1.0 for real-time (1x), 10.0 for 10x speed, float('inf') for max speed.
        """
        self.speed_multiplier = speed_multiplier
        self._is_stopped = False

    def stop(self) -> None:
        """Signals the replay engine to halt."""
        self._is_stopped = True

    def replay_flows(
        self,
        flows: List[BidirectionalFlow],
        event_callback: Callable[[BidirectionalFlow], None],
    ) -> int:
        """
        Replays an ordered list of flows, invoking event_callback for each.
        Preserves relative inter-arrival delays scaled by speed_multiplier.
        """
        if not flows:
            return 0

        self._is_stopped = False
        sorted_flows = sorted(flows, key=lambda f: f.start_timestamp)
        total_replayed = 0

        prev_timestamp = sorted_flows[0].start_timestamp
        start_wall_time = time.monotonic()

        logger.info(
            f"Starting flow replay of {len(sorted_flows)} events at {self.speed_multiplier}x speed."
        )

        for flow in sorted_flows:
            if self._is_stopped:
                logger.info("Replay stopped by user signal.")
                break

            time_delta = flow.start_timestamp - prev_timestamp
            if time_delta > 0 and self.speed_multiplier < float("inf"):
                scaled_delay = time_delta / max(0.0001, self.speed_multiplier)
                # Cap sleep to max 2.0 seconds to prevent hanging on long quiet periods
                time.sleep(min(2.0, scaled_delay))

            event_callback(flow)
            prev_timestamp = flow.start_timestamp
            total_replayed += 1

        elapsed = time.monotonic() - start_wall_time
        logger.info(f"Replay finished: {total_replayed} flows dispatched in {elapsed:.2f}s.")
        return total_replayed
