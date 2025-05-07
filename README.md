# NetCut-like Python GUI

A Python-based network management tool with GUI that allows scanning local networks, viewing connected devices, and performing ARP spoofing attacks (either Man-in-the-Middle or blocking devices).

## Features

- Network scanning to discover all connected devices
- Display device information (IP, MAC, vendor, device type)
- ARP spoofing capabilities:
  - MitM (Man-in-the-Middle) mode
  - Block mode to disconnect devices
- Block/unblock all devices with single-click options
- Interface selection with automatic network range detection
- MAC vendor lookup
- Dark mode interface built with Tkinter

## Installation

```bash
# Install required dependencies
pip install psutil scapy mac-vendor-lookup
```

## Usage

```python
# Run the application
python main.py
```

## How It Works

The application uses ARP spoofing techniques to intercept or block network traffic. The core functionality is split between:

- `main.py`: Contains the GUI and user interaction logic[1]
- `netcut_core.py`: Handles the network operations including scanning and ARP spoofing[2]

The interface allows you to select your network adapter, scan for devices, and choose targets for MitM or blocking operations.