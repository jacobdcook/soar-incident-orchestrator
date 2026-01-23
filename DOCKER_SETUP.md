# Docker Permission Fix Guide

## Problem
When running `docker-compose up`, you get:
```
PermissionError: [Errno 13] Permission denied
```

## Solution

### Step 1: Add your user to the docker group
```bash
sudo usermod -aG docker $USER
```

**What this does**: Adds your user account to the `docker` group, which grants permission to access the Docker daemon socket. This is a standard Linux permission management practice.

### Step 2: Apply the changes
You have two options:

**Option A: Use newgrp (immediate, but only for current session)**
```bash
newgrp docker
```

**Option B: Log out and log back in (permanent)**
- Log out of your Linux session
- Log back in
- The docker group membership will be active

### Step 3: Verify it worked
```bash
groups | grep docker
```
If you see "docker" in the output, you're good to go!

### Step 4: Test Docker access
```bash
docker ps
```
If this runs without errors (even if it shows no containers), permissions are fixed.

## Why This Happens

Docker uses a Unix socket (`/var/run/docker.sock`) that's owned by the `docker` group. By default, only root and members of the `docker` group can access it. Adding your user to the group is the recommended way to use Docker without `sudo`.

## Alternative: Use Sudo (Not Recommended)

If you can't add yourself to the docker group, you can use:
```bash
sudo docker-compose up --build
```

However, this is not recommended because:
- Files created by containers will be owned by root
- You'll need to use `sudo` for all Docker commands
- It's less secure

## Using the Startup Script

The `start.sh` script automatically detects if you need sudo and handles it:
```bash
./start.sh
```

This script checks your permissions and uses `sudo` only if necessary.
