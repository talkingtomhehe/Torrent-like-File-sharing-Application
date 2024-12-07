# Manual Document for BitTorrent-like Network System

## Overview
This project implements a BitTorrent-like network system that allows users to upload and download multi-file torrents from multiple peers concurrently. It includes a tracker, a proxy, and peer nodes. The tracker coordinates the peers, the proxy forwards requests, and the peers handle the actual file transfers.

## Prerequisites
- Python 3.x
- Required Python packages: `requests`, `flask`, `bencodepy`, `tkinter`

## Installation
1. Clone the repository to your local machine.
   ```sh
   git clone https://github.com/talkingtomhehe/Torrent-like-File-sharing-Application.git
2. Install the required Python packages:
   ```sh
   pip install requests flask bencodepy

## Configuration

Update the IP addresses in the configuration files:
- In `tracker.py`, update the `TRACKER\_HOST` with the IP address of the tracker.
- In `configs.py`, update the `TRACKER_ADDR` and `TRACKER_ADDR_PROXY` with the IP address of the tracker.
- In `peer.py`, update the `PROXY_ADDRESS` with the IP address of the tracker.

## Running the Components

### Tracker

Start the tracker:

```sh
python tracker.py
```

### Proxy

Start the proxy:

```sh
python proxy.py
```

### Peer

Start a peer node:

```sh
python peer.py
```

## Using the System

### Tracker Interface

The tracker interface will open in a GUI window.

- Use the "Discover" button to view the list of files being tracked.
- Use the "Node Ping" section to check if a specific node is active by entering its Node ID and clicking "Ping Node".

### Peer Interface

The peer interface will open in a GUI window.

#### Upload a File

- Enter the file name in the "File name" field.
- Click "Upload" to upload the file.
- Alternatively, click "Browse from computer" to select a file from your computer and upload it.

#### Download a File

- Enter the info hash of the file in the "Info hash" field.
- Click "Browse .torrent file" to select a .torrent file.
- Click "Add queue download" to add the file to the download queue.
- Click "Download" to start downloading the file.

#### Search for a File

- Enter a keyword or filename in the "Keyword or filename" field.
- Click "Search" to search for files matching the keyword.

### Log Console

The log console displays messages related to the peer's activities, such as uploads, downloads, and connections.

## Troubleshooting

### Incorrect IP Address

Ensure that the IP addresses in the configuration files are correctly set to the IP address of the tracker and proxy.

### Connection Issues

Ensure that the tracker, proxy, and peers are running and that there are no firewall or network issues blocking the connections.

## Notes

- The system supports multiple peers and can handle concurrent uploads and downloads.
- Ensure that the tracker and proxy are running before starting the peer nodes.
- The system logs various activities, which can be useful for debugging and monitoring.

By following this manual, you should be able to set up, run, and use the BitTorrent-like network system effectively.