"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

Anomaly Storage Module
Handles storage and retrieval of BACnet devices and anomalies using SQLite.
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime


class AnomalyStorage:
    """Storage handler for BACnet devices and anomalies."""
    
    def __init__(self, db_path: str = "bacnet_monitor.db"):
        """
        Initialize the storage.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                instance_number INTEGER PRIMARY KEY,
                ip_addresses TEXT,
                mac_addresses TEXT,
                mstp_addresses TEXT,
                first_seen TEXT,
                last_seen TEXT,
                packet_count INTEGER DEFAULT 0
            )
        """)
        
        # Create anomalies table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                resolved INTEGER DEFAULT 0
            )
        """)
        
        # Create statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_devices INTEGER,
                total_packets INTEGER,
                total_anomalies INTEGER,
                data TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def store_device(self, device: dict):
        """
        Store or update a BACnet device.
        
        Args:
            device: Dictionary containing device information
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        instance_number = device.get('instance_number')
        ip_addresses = json.dumps(device.get('ip_addresses', []))
        mac_addresses = json.dumps(device.get('mac_addresses', []))
        mstp_addresses = json.dumps(device.get('mstp_addresses', []))
        last_seen = device.get('last_seen', datetime.now().isoformat())
        packet_count = device.get('packet_count', 0)
        
        # Check if device exists
        cursor.execute(
            "SELECT instance_number, first_seen FROM devices WHERE instance_number = ?",
            (instance_number,)
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update existing device
            first_seen = existing[1]
            cursor.execute("""
                UPDATE devices 
                SET ip_addresses = ?, 
                    mac_addresses = ?, 
                    mstp_addresses = ?,
                    last_seen = ?,
                    packet_count = packet_count + ?
                WHERE instance_number = ?
            """, (ip_addresses, mac_addresses, mstp_addresses, last_seen, packet_count, instance_number))
        else:
            # Insert new device
            first_seen = last_seen
            cursor.execute("""
                INSERT INTO devices 
                (instance_number, ip_addresses, mac_addresses, mstp_addresses, first_seen, last_seen, packet_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (instance_number, ip_addresses, mac_addresses, mstp_addresses, first_seen, last_seen, packet_count))
        
        conn.commit()
        conn.close()
    
    def store_anomaly(self, anomaly: dict):
        """
        Store a network anomaly.
        
        Args:
            anomaly: Dictionary containing anomaly information
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO anomalies 
            (anomaly_type, severity, description, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (
            anomaly.get('anomaly_type'),
            anomaly.get('severity'),
            anomaly.get('description'),
            json.dumps(anomaly.get('details', {})),
            anomaly.get('timestamp', datetime.now().isoformat())
        ))
        
        conn.commit()
        conn.close()
    
    def get_all_devices(self) -> List[dict]:
        """
        Get all discovered devices.
        
        Returns:
            List of device dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM devices ORDER BY instance_number")
        rows = cursor.fetchall()
        
        devices = []
        for row in rows:
            devices.append({
                'instance_number': row[0],
                'ip_addresses': json.loads(row[1]),
                'mac_addresses': json.loads(row[2]),
                'mstp_addresses': json.loads(row[3]),
                'first_seen': row[4],
                'last_seen': row[5],
                'packet_count': row[6]
            })
        
        conn.close()
        return devices
    
    def get_device_info(self, instance_number: int) -> Optional[dict]:
        """
        Get information about a specific device.
        
        Args:
            instance_number: BACnet device instance number
            
        Returns:
            Device dictionary or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM devices WHERE instance_number = ?", (instance_number,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            return {
                'instance_number': row[0],
                'ip_addresses': json.loads(row[1]),
                'mac_addresses': json.loads(row[2]),
                'mstp_addresses': json.loads(row[3]),
                'first_seen': row[4],
                'last_seen': row[5],
                'packet_count': row[6]
            }
        return None
    
    def get_recent_anomalies(self, limit: int = 50, anomaly_type: Optional[str] = None) -> List[dict]:
        """
        Get recent anomalies.
        
        Args:
            limit: Maximum number of anomalies to return
            anomaly_type: Filter by anomaly type (optional)
            
        Returns:
            List of anomaly dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if anomaly_type:
            cursor.execute("""
                SELECT * FROM anomalies 
                WHERE anomaly_type = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (anomaly_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM anomalies 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
        
        rows = cursor.fetchall()
        
        anomalies = []
        for row in rows:
            anomalies.append({
                'id': row[0],
                'anomaly_type': row[1],
                'severity': row[2],
                'description': row[3],
                'details': json.loads(row[4]) if row[4] else {},
                'timestamp': row[5],
                'resolved': bool(row[6])
            })
        
        conn.close()
        return anomalies
    
    def get_statistics(self) -> dict:
        """
        Get network statistics.
        
        Returns:
            Dictionary containing statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count devices
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        # Count anomalies
        cursor.execute("SELECT COUNT(*) FROM anomalies")
        total_anomalies = cursor.fetchone()[0]
        
        # Count unresolved anomalies
        cursor.execute("SELECT COUNT(*) FROM anomalies WHERE resolved = 0")
        unresolved_anomalies = cursor.fetchone()[0]
        
        # Count by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM anomalies 
            WHERE resolved = 0
            GROUP BY severity
        """)
        severity_counts = dict(cursor.fetchall())
        
        # Count by type
        cursor.execute("""
            SELECT anomaly_type, COUNT(*) 
            FROM anomalies 
            WHERE resolved = 0
            GROUP BY anomaly_type
        """)
        type_counts = dict(cursor.fetchall())
        
        # Total packets
        cursor.execute("SELECT SUM(packet_count) FROM devices")
        total_packets = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_devices': total_devices,
            'total_anomalies': total_anomalies,
            'unresolved_anomalies': unresolved_anomalies,
            'total_packets': total_packets,
            'severity_counts': severity_counts,
            'type_counts': type_counts,
            'last_updated': datetime.now().isoformat()
        }
    
    def mark_anomaly_resolved(self, anomaly_id: int):
        """
        Mark an anomaly as resolved.
        
        Args:
            anomaly_id: ID of the anomaly to resolve
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE anomalies SET resolved = 1 WHERE id = ?",
            (anomaly_id,)
        )
        
        conn.commit()
        conn.close()
    
    def clear_all_data(self):
        """Clear all data from the database (for testing)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM devices")
        cursor.execute("DELETE FROM anomalies")
        cursor.execute("DELETE FROM statistics")
        
        conn.commit()
        conn.close()

