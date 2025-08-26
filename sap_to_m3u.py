#!/usr/bin/env python3

import socket
import struct
import time
import re
import argparse
from datetime import datetime
from typing import List, Dict, Optional

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

class SAPCollector:
    def __init__(self, multicast_group='224.2.127.254', port=9875, interface=None, verbose=False):
        self.multicast_group = multicast_group
        self.port = port
        self.interface = interface
        self.verbose = verbose
        self.sock = None
        self.streams = {}
        self.packet_count = 0
        
    def hexdump(self, data: bytes, width: int = 16):
        """Print hex dump of data"""
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  {i:04x}: {hex_part:<{width*3}} {ascii_part}")
        
    def get_interface_ip(self, interface_name: str) -> str:
        if HAS_NETIFACES:
            try:
                if interface_name in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface_name)
                    if netifaces.AF_INET in addrs:
                        return addrs[netifaces.AF_INET][0]['addr']
                raise ValueError(f"Interface {interface_name} not found or has no IPv4 address")
            except Exception as e:
                raise ValueError(f"Error getting interface IP: {e}")
        else:
            import subprocess
            try:
                result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                                      capture_output=True, text=True, check=True)
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and 'scope global' in line:
                        return line.split()[1].split('/')[0]
                raise ValueError(f"No IPv4 address found for interface {interface_name}")
            except subprocess.CalledProcessError:
                raise ValueError(f"Interface {interface_name} not found")
            except Exception as e:
                raise ValueError(f"Error getting interface IP: {e}")
    
    def setup_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', self.port))
        
        if self.interface:
            try:
                interface_ip = self.get_interface_ip(self.interface)
                print(f"Using interface {self.interface} with IP {interface_ip}")
                mreq = struct.pack('4s4s', socket.inet_aton(self.multicast_group), socket.inet_aton(interface_ip))
            except ValueError as e:
                print(f"Warning: {e}")
                print("Falling back to default interface")
                mreq = struct.pack('4sl', socket.inet_aton(self.multicast_group), socket.INADDR_ANY)
        else:
            mreq = struct.pack('4sl', socket.inet_aton(self.multicast_group), socket.INADDR_ANY)
            
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.sock.settimeout(1.0)
        
    def parse_sdp(self, data: bytes) -> Optional[Dict]:
        try:
            sdp_text = data.decode('utf-8', errors='ignore')
            if self.verbose:
                print(f"\nSDP content:\n{sdp_text[:500]}{'...' if len(sdp_text) > 500 else ''}")
            lines = sdp_text.strip().split('\n')
            
            session_info = {
                'name': '',
                'description': '',
                'url': '',
                'connection': '',
                'media_port': '',
                'media_type': '',
                'group': '',
                'timestamp': datetime.now().isoformat()
            }
            
            for line in lines:
                line = line.strip()
                if line.startswith('s='):
                    session_info['name'] = line[2:]
                elif line.startswith('i='):
                    session_info['description'] = line[2:]
                elif line.startswith('u='):
                    session_info['url'] = line[2:]
                elif line.startswith('c='):
                    session_info['connection'] = line[2:]
                elif line.startswith('m='):
                    parts = line[2:].split()
                    if len(parts) >= 3:
                        session_info['media_type'] = parts[0]
                        session_info['media_port'] = parts[1]
                elif line.startswith('a=x-plgroup:'):
                    session_info['group'] = line[12:]
                    if self.verbose:
                        print(f"Found group: {session_info['group']}")
                        
            if session_info['connection'] and session_info['media_port']:
                conn_parts = session_info['connection'].split()
                if len(conn_parts) >= 3:
                    ip = conn_parts[2].split('/')[0]
                    port = session_info['media_port']
                    session_info['stream_url'] = f"rtp://{ip}:{port}"
                    
            return session_info if session_info['name'] else None
            
        except Exception as e:
            print(f"Error parsing SDP: {e}")
            return None
    
    def parse_sap_packet(self, data: bytes) -> Optional[Dict]:
        if self.verbose:
            print(f"\nPacket #{self.packet_count + 1}: {len(data)} bytes")
            self.hexdump(data[:min(64, len(data))])
            
        if len(data) < 4:
            if self.verbose:
                print("Packet too short (< 4 bytes)")
            return None
            
        header = struct.unpack('!BBH', data[:4])
        version = (header[0] & 0xE0) >> 5
        address_type = (header[0] & 0x10) >> 4
        reserved = (header[0] & 0x08) >> 3
        message_type = (header[0] & 0x04) >> 2
        encrypted = (header[0] & 0x02) >> 1
        compressed = header[0] & 0x01
        
        auth_len = header[1]
        msg_id_hash = header[2]
        
        if self.verbose:
            print(f"SAP Header: version={version}, addr_type={address_type}, msg_type={message_type}")
            print(f"Auth len={auth_len}, msg_hash={msg_id_hash}, encrypted={encrypted}, compressed={compressed}")
        
        if version != 1:
            if self.verbose:
                print(f"Unsupported SAP version: {version}")
            return None
            
        if compressed:
            if self.verbose:
                print("Compressed SAP packets not supported")
            return None
            
        if encrypted:
            if self.verbose:
                print("Encrypted SAP packets not supported")
            return None
        
        # Skip origin source (4 bytes) + auth data
        offset = 8 + auth_len * 4
        if len(data) <= offset:
            if self.verbose:
                print(f"Packet too short for payload (need {offset}, got {len(data)})")
            return None
            
        if self.verbose:
            print(f"Payload starts at offset {offset}")
            
        # Look for MIME type (null-terminated string)
        payload = data[offset:]
        mime_type_end = payload.find(b'\0')
        
        if mime_type_end == -1:
            # Try without MIME type separator (some implementations)
            if self.verbose:
                print("No MIME type separator found, trying direct SDP parse")
            sdp_data = payload
            mime_type = "application/sdp"
        else:
            mime_type = payload[:mime_type_end].decode('ascii', errors='ignore')
            sdp_data = payload[mime_type_end + 1:]
            
        if self.verbose:
            print(f"MIME type: '{mime_type}'")
            print(f"SDP data ({len(sdp_data)} bytes): {sdp_data[:200]}...")
        
        if mime_type == 'application/sdp' or not mime_type:
            return self.parse_sdp(sdp_data)
        else:
            if self.verbose:
                print(f"Unsupported MIME type: {mime_type}")
            return None
    
    def collect_announcements(self, duration: int = 60) -> Dict:
        self.setup_socket()
        start_time = time.time()
        
        print(f"Listening for SAP announcements for {duration} seconds...")
        
        while time.time() - start_time < duration:
            try:
                data, addr = self.sock.recvfrom(1024)
                session_info = self.parse_sap_packet(data)
                
                if session_info and session_info.get('stream_url'):
                    stream_id = session_info['stream_url']
                    if stream_id not in self.streams:
                        self.streams[stream_id] = session_info
                        print(f"Found stream: {session_info['name']} - {stream_id}")
                        
                self.packet_count += 1
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving data: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                
        self.sock.close()
        return self.streams
    
    def generate_m3u(self, output_file: str = 'sap_streams.m3u'):
        if not self.streams:
            print("No streams found to generate playlist")
            return
            
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n')
            
            for stream_url, info in self.streams.items():
                name = info['name'] or 'Unknown Stream'
                description = info['description'] or ''
                group = info.get('group', '')
                
                # Add group tag if available
                if group:
                    f.write(f"#EXTGRP:{group}\n")
                
                # Generate tvg-id from stream URL or name
                tvg_id = stream_url.replace('rtp://', '').replace(':', '_').replace('/', '_')
                tvg_name = name
                group_title = group or 'General'
                
                # Build EXTINF line with TVG attributes
                extinf_line = f'#EXTINF:-1 tvg-id="{tvg_id}" tvg-name="{tvg_name}" group-title="{group_title}"'
                if description:
                    extinf_line += f',{name} - {description}'
                else:
                    extinf_line += f',{name}'
                
                f.write(f"{extinf_line}\n")
                f.write(f"{stream_url}\n")
                
        print(f"M3U playlist generated: {output_file}")
        print(f"Total streams: {len(self.streams)}")

def main():
    parser = argparse.ArgumentParser(description='Collect SAP announcements and generate M3U playlist')
    parser.add_argument('-d', '--duration', type=int, default=15, 
                       help='Duration to listen for announcements (seconds)')
    parser.add_argument('-o', '--output', default='sap_streams.m3u',
                       help='Output M3U file name')
    parser.add_argument('-g', '--group', default='224.2.127.254',
                       help='Multicast group address')
    parser.add_argument('-p', '--port', type=int, default=9875,
                       help='SAP port number')
    parser.add_argument('-i', '--interface', 
                       help='Network interface to use for multicast (e.g., eth0, wlan0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose debug output')
    
    args = parser.parse_args()
    
    collector = SAPCollector(args.group, args.port, args.interface, args.verbose)
    
    try:
        streams = collector.collect_announcements(args.duration)
        collector.generate_m3u(args.output)
        
        if streams:
            print("\nFound streams:")
            for url, info in streams.items():
                print(f"  {info['name']} - {url}")
        else:
            print("No SAP announcements found")
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
