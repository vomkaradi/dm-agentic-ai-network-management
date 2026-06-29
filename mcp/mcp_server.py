"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause
"""

import asyncio
import inspect
import sys
from fastmcp import FastMCP
from fastmcp.dependencies import Progress
from fastmcp.utilities.logging import get_logger
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bacnet.anomaly_storage import AnomalyStorage
from bacnet.pcap_monitor import PCAPMonitor

logger = get_logger(__name__)


class DeviceInfo(BaseModel):
    instance_number: int
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    mstp_addresses: list[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    packet_count: int = 0

class DevicesResponse(BaseModel):
    status: str
    count: int
    devices: list[DeviceInfo]

class AnomalyInfo(BaseModel):
    id: int
    anomaly_type: str
    severity: str
    description: str
    details: dict = Field(default_factory=dict)
    timestamp: str
    resolved: bool = False

class AnomaliesResponse(BaseModel):
    status: str
    count: int
    anomalies: list[AnomalyInfo]

class StatisticsInfo(BaseModel):
    total_devices: int = 0
    total_anomalies: int = 0
    unresolved_anomalies: int = 0
    total_packets: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    type_counts: dict[str, int] = Field(default_factory=dict)
    last_updated: str = ""

class StatisticsResponse(BaseModel):
    status: str
    statistics: StatisticsInfo

class DeviceDetailResponse(BaseModel):
    status: str
    device: Optional[DeviceInfo] = None
    error_message: Optional[str] = None

class ResolveAnomalyResponse(BaseModel):
    status: str
    anomaly_id: int
    message: str

# Initialize the server
mcp = FastMCP("BACnet Security MCP Server")

# Initialize storage
storage = AnomalyStorage()

@mcp.tool()
def get_bacnet_anomalies(limit: int = 5) -> AnomaliesResponse:
    """Retrieves recent BACnet network anomalies.

    Args:
        limit: Last number of anomalies to retrieve ordered by most recent first (default: 5).

    Returns:
        AnomaliesResponse: List of recent anomalies.
    """
    logger.info(f"Tool: get_bacnet_anomalies called with limit={limit}")
    anomalies = storage.get_recent_anomalies(limit=limit)
    return AnomaliesResponse(
        status="success",
        anomalies=[AnomalyInfo(**a) for a in anomalies],
        count=len(anomalies),
    )


@mcp.tool()
def get_network_statistics() -> StatisticsResponse:
    """Retrieves BACnet network statistics and health metrics.

    Returns:
        StatisticsResponse: Network statistics and metrics.
    """
    logger.info("Tool: get_network_statistics called")
    stats = storage.get_statistics()
    return StatisticsResponse(status="success", statistics=stats)


@mcp.tool()
def get_device_details(instance_number: int) -> DeviceDetailResponse:
    """Retrieves detailed information about a specific BACnet device.

    Args:
        instance_number: The BACnet device instance number.

    Returns:
        DeviceDetailResponse: Device details or error message.
    """
    logger.info(f"Tool: get_device_details called for instance {instance_number}")
    device = storage.get_device_info(instance_number)

    if device:
        return DeviceDetailResponse(
            status="success",
            device=DeviceInfo(**device),
        )
    else:
        return DeviceDetailResponse(
            status="error",
            error_message=f"Device instance {instance_number} not found",
        )


# Run the server
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8081)
