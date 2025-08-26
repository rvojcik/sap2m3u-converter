#!/usr/bin/env python3

import socket
import struct

def test_multicast_capture():
    multicast_group = '224.2.127.254'
    port = 9875
    
    print(f"Testing multicast capture on {multicast_group}:{port}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('', port))
        print("Socket bound successfully")
        
        mreq = struct.pack('4sl', socket.inet_aton(multicast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print("Joined multicast group")
        
        sock.settimeout(5.0)
        
        print("Listening for packets for 5 seconds...")
        packet_count = 0
        
        while packet_count < 10:
            try:
                data, addr = sock.recvfrom(1024)
                packet_count += 1
                print(f"Packet #{packet_count}: {len(data)} bytes from {addr}")
                print(f"First 32 bytes: {data[:32].hex()}")
                
                if packet_count >= 10:
                    break
                    
            except socket.timeout:
                print("Timeout - no more packets")
                break
                
        if packet_count == 0:
            print("No packets received")
        else:
            print(f"Captured {packet_count} packets")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    test_multicast_capture()