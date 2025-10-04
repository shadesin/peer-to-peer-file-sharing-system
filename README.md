# Peer-to-Peer File Sharing System

## Overview
This project implements a peer-to-peer (P2P) file sharing system with **two redundant trackers** for fault tolerance and synchronization.  
It supports:
- User and group management
- File upload and download with piece-level integrity verification (SHA1)
- Automatic seeding after downloads
- Parallel multi-peer downloads
- Tracker synchronization using a shared file (`tracker_sync.txt`)

---

## Compilation Instructions

### Tracker
```bash
cd tracker
make
```
This builds the `tracker` executable.

### Client
```bash
cd client
make
```
This builds the `client` executable.  
Compilation requires:
- `-std=c++17`
- `pthread`
- `OpenSSL 3` (for SHA1)

Install OpenSSL 3 on macOS:
```bash
brew install openssl@3
```

---

## Execution Instructions

1. **Start Trackers**  
   Start each tracker with its tracker number (1 or 2):
   ```bash
   ./tracker tracker_info.txt 1
   ./tracker tracker_info.txt 2
   ```
   Example `tracker_info.txt`:
   ```
   127.0.0.1:5001
   127.0.0.1:6001
   ```

2. **Start Client**  
   Run each client with its listening IP:PORT and tracker_info.txt:
   ```bash
   ./client 127.0.0.1:7000 tracker_info.txt
   ```
   Here `7000` is the client listening port for peer-to-peer transfers.  
   Clients auto-connect to an available tracker and fail over seamlessly if one fails.

---

## Commands Available

### User and Group Management
- `create_user <uid> <password>` — Register a new user.
- `login <uid> <password>` — Login as an existing user.
- `logout` — Logout from the current session.
- `create_group <gid>` — Create a new group.
- `join_group <gid>` — Request to join a group.
- `leave_group <gid>` — Leave a group. (Group owner cannot leave.)
- `list_groups` — List all available groups.
- `list_requests <gid>` — List join requests for a group (visible to owner).
- `accept_request <gid> <uid>` — Accept a join request.

### File Sharing
- `upload_file <gid> <filepath>`  
  Uploads a file to a group. File is split into 512KB pieces, each hashed with SHA1.
- `list_files <gid>` — List all files available in a group.
- `download_file <gid> <filename> <destination_path>`  
  Downloads a file. Pieces are fetched in parallel from peers, verified with SHA1, and stored to disk.  
  On success, the client automatically becomes a seeder.
- `stop_share <gid> <filename>` — Stop sharing a file from the current client only.

### Status
- `show_downloads`  
  - `[C] gid filename` — Completed download.  
  - `[D] gid filename <percent>%` — Download in progress.

---

## Data Structures Used

### Tracker
- `map<string,string>` — Users and their passwords.
- `map<string,string>` — Group owners.
- `map<string,set<string>>` — Group members.
- `map<string,vector<string>>` — Join requests (order preserved).
- `map<string,vector<FileInfo>>` — Files shared in each group.

### Client
- `map<string,string>` — Shared files (filename → full path).
- `map<string,DownloadStatus>` — Tracks download progress per file.
- `DownloadStatus` struct with:
  - `gid`, `filename`, `destpath`
  - `atomic<int>` pieces_done
  - `bool completed`

### Rationale
- **map** → Efficient O(log n) lookup.
- **set** → Prevent duplicate group members.
- **vector** → Preserve insertion order (e.g., join requests, file piece hashes).
- **atomic<int>** → Thread-safe counters for downloads.
- **mutex** → Protect shared maps (`shared_files`, `downloads`).

---

## Protocol Design
- **Client → Tracker**: Commands like `create_user`, `upload_file`, `download_file`.
- **Tracker → Client**: Replies with SUCCESS/ERROR and metadata (PEERS, NUM, FILEHASH, FILESIZE, PIECES).
- **Client → Client**: `GET <filename> <piece_index>`, returns raw piece data.
- **Tracker → Tracker**: SYNC messages containing state snapshots.

All communication is TCP-based with lightweight custom framing.

---

## Assumptions
- Maximum file size: ~1 GB.
- Fixed piece size: 512 KB.
- SHA1 chosen for integrity verification.
- At least one tracker is always running (otherwise `tracker_sync.txt` is deleted).
- Filenames are unique within a group.

---

## Limitations
- Group owner cannot leave group.
- SHA1 is not cryptographically strong.
- File paths with spaces must be quoted.
- Tested only on macOS (Apple Silicon). Linux adjustments may be needed.

---

## Testing Procedures
- **User/Group Tests**: Create user, login/logout, group creation, join/leave, accept requests.
- **File Upload/Download**: Test with small (<1 MB), medium (~50 MB), and large (~1 GB) files.
- **Multi-Peer Downloads**: Upload from multiple peers, then download to check multi-source piece fetching.
- **Tracker Failover**: Kill one tracker during operation; ensure auto-reconnect.
- **Stop Share**: Verify removing one seeder still allows downloads from others.

---
