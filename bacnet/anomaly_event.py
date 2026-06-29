"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

"""

import asyncio
from typing import Dict, Any


class AnomalyEvent:
    """
    Event-based system for anomaly notifications.
    Allows multiple consumers to wait for anomaly events.
    """

    def __init__(self):
        self._queue = asyncio.Queue()

    async def notify(self, anomaly_data: Dict[str, Any]):
        """
        Notify all waiters of a new anomaly.
    
        Args:
            anomaly_data: Dictionary containing anomaly information
        """
        await self._queue.put(anomaly_data)

    async def wait_for_anomaly(self) -> Dict[str, Any]:
        """
        Wait for the next anomaly event.
    
        Returns:
            Dictionary containing anomaly information
        """
        return await self._queue.get()