"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

PCAP File Monitor for BACnet Network Analysis
Continuously processes PCAP files in a loop to simulate real network monitoring.
"""


import asyncio
from pathlib import Path
from typing import List
from datetime import datetime

from .anomaly_storage import AnomalyStorage
from .bacnet_parser import BACnetParser
from .anomaly_event import AnomalyEvent

class PCAPMonitor:
    """
    Monitors PCAP files and processes them continuously in a loop.
    Simulates real-time network monitoring by processing files repeatedly.
    """
    
    def __init__(self, pcap_directory: str, poll_interval: int = 60):
        """
        Initialize the PCAP monitor.
        
        Args:
            pcap_directory: Directory containing PCAP files
            poll_interval: Seconds between processing each file (default: 60)
        """
        self.pcap_directory = Path(pcap_directory)
        self.poll_interval = poll_interval
        self.storage = AnomalyStorage()
        self.parser = BACnetParser()
        self.running = False
        self.anomaly_event = AnomalyEvent()
        
        # Ensure directory exists
        self.pcap_directory.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] PCAP Monitor initialized")
        print(f"[*] Directory: {self.pcap_directory}")
        print(f"[*] Processing interval: {self.poll_interval} seconds")
    
    def get_pcap_files(self) -> List[Path]:
        """Get all PCAP files in the directory."""
        pcap_extensions = ['.pcap', '.cap', '.pcapng']
        files = []
        
        for ext in pcap_extensions:
            files.extend(self.pcap_directory.glob(f'*{ext}'))
        
        return sorted(files)
    
    async def process_file(self, file_path: Path):
        """Process a single PCAP file."""
        try:
            print(f"\n[*] Processing: {file_path.name}")
            print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Parse the PCAP file
            results = self.parser.analyze_pcap(str(file_path))
            
            if not results:
                print(f"[!] No BACnet data found in {file_path.name}")
                return
            
            # Store devices
            for device in results.get('devices', []):
                self.storage.store_device(device)
            
            # Store and notify anomalies
            anomalies = results.get('anomalies', [])
            
            if anomalies:
                print(f"[!] Found {len(anomalies)} anomalies")
                
                for anomaly in anomalies:
                    # Don't include source_file in the anomaly data
                    anomaly_data = {
                        'anomaly_type': anomaly['type'],
                        'severity': anomaly['severity'],
                        'description': anomaly['description'],
                        'details': anomaly.get('details', {}),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Store in database
                    self.storage.store_anomaly(anomaly_data)
                    
                    # Notify via event system
                    await self.anomaly_event.notify(anomaly_data)
                    
                    print(f"  - {anomaly['type']}: {anomaly['description']}")
                    
                    await asyncio.sleep(self.poll_interval)
            else:
                print(f"[✓] No anomalies detected")
            
            # Store statistics
            stats = results.get('statistics', {})
            if stats:
                print(f"[*] Devices: {stats.get('total_devices', 0)}, "
                      f"Packets: {stats.get('total_packets', 0)}")
        
        except Exception as e:
            print(f"[!] Error processing {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
    
    async def start(self):
        """Start continuous monitoring loop."""
        self.running = True
        print("\n" + "=" * 70)
        print("BACnet PCAP Monitor - Continuous Processing Mode")
        print("=" * 70)
        print(f"Monitoring directory: {self.pcap_directory}")
        print(f"Processing interval: {self.poll_interval} seconds")
        print("Press Ctrl+C to stop")
        print("=" * 70 + "\n")
        
        cycle_count = 0
        
        while self.running:
            try:
                # Get all PCAP files
                pcap_files = self.get_pcap_files()
                
                if not pcap_files:
                    print(f"[!] No PCAP files found in {self.pcap_directory}")
                    print(f"[*] Waiting {self.poll_interval} seconds before retry...")
                    await asyncio.sleep(self.poll_interval)
                    continue
                
                cycle_count += 1
                print(f"\n{'=' * 70}")
                print(f"Processing Cycle #{cycle_count}")
                print(f"Files to process: {len(pcap_files)}")
                print(f"{'=' * 70}")
                
                # Process each file
                for file_path in pcap_files:
                    if not self.running:
                        break
                    
                    await self.process_file(file_path)
                    
                    # Wait between files
                    if file_path != pcap_files[-1]:  # Don't wait after last file
                        print(f"\n[*] Waiting {self.poll_interval} seconds before next file...")
                        #await asyncio.sleep(self.poll_interval)
                
                # After processing all files, wait before starting next cycle
                if self.running:
                    print(f"\n[*] Cycle #{cycle_count} complete")
                    print(f"[*] Waiting {self.poll_interval} seconds before next cycle...")
                    #await asyncio.sleep(self.poll_interval)
            
            except asyncio.CancelledError:
                print("\n[*] Monitor stopped")
                break
            except Exception as e:
                print(f"\n[!] Error in monitoring loop: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(self.poll_interval)
    
    def stop(self):
        """Stop the monitoring loop."""
        print("\n[*] Stopping PCAP monitor...")
        self.running = False

