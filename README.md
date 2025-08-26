# SAP to M3U Converter

A Python script that collects SAP (Session Announcement Protocol) streaming announcements and converts them into M3U playlist format with IPTV-compatible metadata including TVG attributes and group information.

## Usage

```bash
python3 sap_to_m3u.py [options]
```

## Options

- `-d, --duration`: Duration to listen for announcements in seconds (default: 60)
- `-o, --output`: Output M3U file name (default: sap_streams.m3u)  
- `-g, --group`: Multicast group address (default: 224.2.127.254)
- `-p, --port`: SAP port number (default: 9875)
- `-i, --interface`: Network interface to use for multicast (e.g., eth0, wlan0)
- `-v, --verbose`: Enable verbose debug output

## Examples

```bash
# Listen for 2 minutes and save to custom file
python3 sap_to_m3u.py -d 120 -o my_streams.m3u

# Use custom multicast group
python3 sap_to_m3u.py -g 239.255.255.255 -p 9875

# Use specific network interface
python3 sap_to_m3u.py -i eth0

# Combine options
python3 sap_to_m3u.py -i wlan0 -d 300 -o wifi_streams.m3u

# Debug packet parsing issues
python3 sap_to_m3u.py -v -d 30
```

## Debugging

If the script reports "No SAP announcements found" but you see traffic with tcpdump:

1. **Test basic packet capture**:
   ```bash
   python3 test_capture.py
   ```

2. **Enable verbose output** to see raw packet data:
   ```bash
   python3 sap_to_m3u.py -v -d 30
   ```

3. **Check with tcpdump** what's actually being received:
   ```bash
   sudo tcpdump -i any -n host 224.2.127.254 and port 9875
   ```

## Features

- **SAP Protocol Support**: Listens for SAP/SDP announcements on multicast networks
- **IPTV-Compatible Output**: Generates M3U playlists with TVG attributes for modern players
- **Group Support**: Extracts and uses `a=x-plgroup` for channel organization
- **Network Interface Selection**: Choose specific network interfaces for multicast
- **Verbose Debugging**: Detailed packet analysis and parsing information
- **Cross-Platform**: Works on Linux systems with Python 3.x

## Requirements

- Python 3.x
- Network access to SAP multicast announcements
- Root privileges may be required for multicast socket binding
- Optional: `netifaces` package for enhanced interface handling (`pip install netifaces`)

## Output

The script generates an M3U playlist file with enhanced metadata format:

```
#EXTM3U
#EXTGRP:Sports
#EXTINF:-1 tvg-id="239.1.1.100_5000" tvg-name="ESPN HD" group-title="Sports",ESPN HD
rtp://239.1.1.100:5000
#EXTGRP:News  
#EXTINF:-1 tvg-id="239.1.1.101_5000" tvg-name="CNN International" group-title="News",CNN International
rtp://239.1.1.101:5000
```

**M3U Attributes:**
- `tvg-id`: Generated from stream URL for unique identification  
- `tvg-name`: Channel name from SDP session name (`s=` field)
- `group-title`: Group from `a=x-plgroup` SDP attribute or "General" if not specified
- `#EXTGRP`: Additional group tag for better player compatibility

**SDP Fields Parsed:**
- `s=`: Session name (becomes channel name)
- `i=`: Session description (appended to channel name)
- `c=`: Connection information (IP address and port)
- `m=`: Media description (media type and port)
- `a=x-plgroup:`: Playlist group for channel organization

## How It Works

1. **Multicast Listening**: Binds to SAP multicast group (224.2.127.254:9875)
2. **SAP Packet Parsing**: Decodes SAP headers and extracts SDP payload
3. **SDP Analysis**: Parses session descriptions to extract stream metadata
4. **M3U Generation**: Creates IPTV-compatible playlists with enhanced attributes

## Use Cases

- **IPTV Discovery**: Automatically discover available streams on network
- **Network Monitoring**: Monitor SAP announcements for stream availability
- **Playlist Creation**: Generate organized channel lists for media players
- **Stream Analysis**: Debug and analyze multicast streaming setups