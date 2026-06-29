"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

BACnet Protocol Parser
Extracts device information and detects anomalies from BACnet packets.
"""

from scapy.all import rdpcap, IP, UDP, Ether, Raw, ARP
from collections import defaultdict
from typing import Dict, Set, List, Optional, Tuple
from datetime import datetime


class BACnetParser:
    """Parser for BACnet protocol packets."""
    
    def __init__(self):
        self.device_instances = defaultdict(list)
        self.ip_to_instances = defaultdict(set)
        self.ip_to_macs = defaultdict(set)
        self.mac_to_ips = defaultdict(set)
        self.mstp_to_instances = defaultdict(set)
        self.device_info = {}
        self.arp_table = defaultdict(set)
        self.ip_packet_count = defaultdict(lambda: defaultdict(int))
    
    def analyze_pcap(self, pcap_file: str) -> dict:
        """
        Analyze a PCAP file for BACnet traffic.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            dict: Analysis results containing devices, anomalies, and statistics
        """
        # Reset state for new file
        self.device_instances.clear()
        self.ip_to_instances.clear()
        self.ip_to_macs.clear()
        self.mac_to_ips.clear()
        self.mstp_to_instances.clear()
        self.device_info.clear()
        self.arp_table.clear()
        self.ip_packet_count.clear()
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"[!] Error reading pcap file: {e}")
            return {}
        
        bacnet_ip_packets = 0
        bacnet_mstp_packets = 0
        arp_packets = 0
        
        for pkt in packets:
            src_ip = None
            src_mac = None
            mstp_addr = None
            instance = None
            
            # Check for ARP packets
            if ARP in pkt:
                arp_packets += 1
                if pkt[ARP].op in [1, 2]:
                    sender_ip = pkt[ARP].psrc
                    sender_mac = pkt[ARP].hwsrc
                    self.arp_table[sender_ip].add(sender_mac)
                    self.ip_to_macs[sender_ip].add(sender_mac)
                    self.mac_to_ips[sender_mac].add(sender_ip)
            
            # Try BACnet/IP (UDP port 47808)
            if IP in pkt and UDP in pkt:
                if pkt[UDP].dport == 47808 or pkt[UDP].sport == 47808:
                    bacnet_ip_packets += 1
                    src_ip = pkt[IP].src
                    
                    if Ether in pkt:
                        src_mac = pkt[Ether].src
                        self.mac_to_ips[src_mac].add(src_ip)
                        self.ip_to_macs[src_ip].add(src_mac)
                        self.ip_packet_count[src_ip][src_mac] += 1
                    
                    payload = bytes(pkt[UDP].payload)
                    npdu = self.parse_bacnet_npdu(payload)
                    
                    if npdu:
                        instance = self.parse_bacnet_apdu(npdu)
            
            # Try BACnet MS/TP
            elif Raw in pkt or Ether in pkt:
                payload = bytes(pkt[Raw].load) if Raw in pkt else bytes(pkt)
                npdu, mstp_addr = self.parse_bacnet_mstp(payload)
                
                if npdu and mstp_addr is not None:
                    bacnet_mstp_packets += 1
                    instance = self.parse_bacnet_apdu(npdu)
                    
                    if Ether in pkt:
                        src_mac = pkt[Ether].src
            
            # Record device instance information
            if instance is not None:
                if instance not in self.device_info:
                    self.device_info[instance] = {
                        'ips': set(),
                        'mstp': set(),
                        'macs': set()
                    }
                
                if src_ip:
                    self.device_instances[instance].append(src_ip)
                    self.ip_to_instances[src_ip].add(instance)
                    self.device_info[instance]['ips'].add(src_ip)
                
                if mstp_addr is not None:
                    self.device_instances[instance].append(f"MS/TP:{mstp_addr}")
                    self.mstp_to_instances[mstp_addr].add(instance)
                    self.device_info[instance]['mstp'].add(mstp_addr)
                
                if src_mac:
                    self.device_info[instance]['macs'].add(src_mac)
        
        # Generate results
        devices = self._extract_devices()
        anomalies = self._detect_anomalies()
        statistics = {
            'total_packets': len(packets),
            'bacnet_ip_packets': bacnet_ip_packets,
            'bacnet_mstp_packets': bacnet_mstp_packets,
            'arp_packets': arp_packets,
            'total_devices': len(self.device_info),
            'total_anomalies': len(anomalies)
        }
        
        return {
            'devices': devices,
            'anomalies': anomalies,
            'statistics': statistics
        }
    
    def _extract_devices(self) -> List[dict]:
        """Extract device information."""
        devices = []
        
        for instance, info in self.device_info.items():
            devices.append({
                'instance_number': instance,
                'ip_addresses': list(info['ips']),
                'mac_addresses': list(info['macs']),
                'mstp_addresses': list(info['mstp']),
                'last_seen': datetime.now().isoformat(),
                'packet_count': sum(
                    sum(self.ip_packet_count[ip].values()) 
                    for ip in info['ips']
                )
            })
        
        return devices
    
    def _detect_anomalies(self) -> List[dict]:
        """Detect network anomalies."""
        anomalies = []
        
        # 1. Duplicate IP addresses
        for ip, macs in self.ip_to_macs.items():
            if len(macs) > 1:
                anomalies.append({
                    'type': 'duplicate_ip',
                    'severity': 'critical',
                    'description': f'Duplicate IP address {ip} detected on {len(macs)} different devices',
                    'details': {
                        'ip_address': ip,
                        'mac_addresses': list(macs),
                        'packet_counts': {
                            mac: self.ip_packet_count[ip][mac] 
                            for mac in macs
                        }
                    }
                })
        
        # 2. Duplicate device instance numbers
        for instance, addr_list in self.device_instances.items():
            unique_addrs = set(addr_list)
            if len(unique_addrs) > 1:
                anomalies.append({
                    'type': 'duplicate_instance',
                    'severity': 'high',
                    'description': f'Device instance {instance} found on multiple addresses',
                    'details': {
                        'instance_number': instance,
                        'addresses': list(unique_addrs)
                    }
                })
        
        # 3. IP addresses with multiple device instances
        for ip, instances in self.ip_to_instances.items():
            if len(instances) > 1:
                macs = list(self.ip_to_macs.get(ip, set()))
                anomalies.append({
                    'type': 'multi_instance_ip',
                    'severity': 'high',
                    'description': f'IP address {ip} is used by {len(instances)} different device instances',
                    'details': {
                        'ip_address': ip,
                        'mac_addresses': macs,
                        'instance_numbers': list(instances)
                    }
                })
        
        # 4. MAC addresses with multiple IPs
        for mac, ips in self.mac_to_ips.items():
            if len(ips) > 1:
                anomalies.append({
                    'type': 'mac_multi_ip',
                    'severity': 'medium',
                    'description': f'MAC address {mac} seen with {len(ips)} different IP addresses',
                    'details': {
                        'mac_address': mac,
                        'ip_addresses': list(ips)
                    }
                })
        
        # 5. ARP conflicts
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                anomalies.append({
                    'type': 'arp_conflict',
                    'severity': 'critical',
                    'description': f'ARP conflict for IP {ip}: multiple MAC addresses claiming this IP',
                    'details': {
                        'ip_address': ip,
                        'mac_addresses': list(macs)
                    }
                })
        
        # 6. MS/TP address conflicts
        for mstp_addr, instances in self.mstp_to_instances.items():
            if len(instances) > 1:
                anomalies.append({
                    'type': 'mstp_conflict',
                    'severity': 'high',
                    'description': f'MS/TP address {mstp_addr} is used by {len(instances)} different device instances',
                    'details': {
                        'mstp_address': mstp_addr,
                        'instance_numbers': list(instances)
                    }
                })
        
        return anomalies
    
    def parse_bacnet_npdu(self, payload: bytes) -> Optional[bytes]:
        """Parse BACnet NPDU layer."""
        if len(payload) < 4:
            return None
        
        bvlc_type = payload[0]
        bvlc_length = int.from_bytes(payload[2:4], 'big')
        
        if bvlc_type != 0x81:
            return None
        
        if len(payload) < bvlc_length:
            return None
        
        npdu_start = 4
        return payload[npdu_start:]
    
    def parse_bacnet_mstp(self, payload: bytes) -> Tuple[Optional[bytes], Optional[int]]:
        """Parse BACnet MS/TP frame."""
        if len(payload) < 8:
            return None, None
        
        idx = 0
        while idx < len(payload) - 8:
            if payload[idx] == 0x55 and payload[idx + 1] == 0xFF:
                frame_type = payload[idx + 2]
                src_addr = payload[idx + 4]
                length = int.from_bytes(payload[idx + 5:idx + 7], 'big')
                
                if frame_type in [5, 6] and length > 0:
                    data_start = idx + 8
                    if data_start + length <= len(payload):
                        npdu = payload[data_start:data_start + length]
                        return npdu, src_addr
                
                idx += 1
            else:
                idx += 1
        
        return None, None
    
    def parse_bacnet_apdu(self, npdu: bytes) -> Optional[int]:
        """Parse BACnet APDU and extract device instance."""
        if not npdu or len(npdu) < 2:
            return None
        
        version = npdu[0]
        if version != 0x01:
            return None
        
        control = npdu[1]
        offset = 2
        
        if control & 0x20:
            if len(npdu) < offset + 3:
                return None
            dlen = npdu[offset + 2]
            offset += 3 + dlen + 1
        
        if control & 0x08:
            if len(npdu) < offset + 3:
                return None
            slen = npdu[offset + 2]
            offset += 3 + slen
        
        if len(npdu) <= offset:
            return None
        
        apdu = npdu[offset:]
        return self.extract_device_instance(apdu)
    
    def extract_device_instance(self, apdu: bytes) -> Optional[int]:
        """Extract device instance number from APDU."""
        if not apdu or len(apdu) < 1:
            return None
        
        pdu_type = (apdu[0] >> 4) & 0x0F
        
        if pdu_type == 0x01:
            if len(apdu) < 2:
                return None
            service_choice = apdu[1]
            
            if service_choice == 0x00:
                return self.parse_i_am(apdu[2:])
        
        return self.search_device_object(apdu)
    
    def parse_i_am(self, data: bytes) -> Optional[int]:
        """Parse I-Am message to extract device instance."""
        if len(data) < 4:
            return None
        
        idx = 0
        while idx < len(data) - 4:
            tag = data[idx]
            
            if tag == 0xC4:
                if idx + 4 < len(data):
                    obj_id = int.from_bytes(data[idx+1:idx+5], 'big')
                    obj_type = (obj_id >> 22) & 0x3FF
                    instance = obj_id & 0x3FFFFF
                    
                    if obj_type == 8:
                        return instance
                idx += 5
            else:
                idx += 1
        
        return None
    
    def search_device_object(self, apdu: bytes) -> Optional[int]:
        """Search for device object references in APDU."""
        for i in range(len(apdu) - 4):
            if apdu[i] in [0x0C, 0xC4, 0x1C]:
                if i + 4 < len(apdu):
                    obj_id = int.from_bytes(apdu[i+1:i+5], 'big')
                    obj_type = (obj_id >> 22) & 0x3FF
                    instance = obj_id & 0x3FFFFF
                    
                    if obj_type == 8 and instance < 0x3FFFFF:
                        return instance
        
        return None

