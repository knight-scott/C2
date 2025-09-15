# Portable Field Kit / Lab C2 Stack

This repository contains scripts, configurations, and documentation for a **portable cybersecurity field kit** with lab C2 testing capabilities.  
It is designed to support **temporary lab C2 servers**, lightweight redirectors, and eventual deployment to 4G/5G mobile hardware, while keeping components **ephemeral, modular, and recoverable**.

> **Disclaimer:** This repository is for **educational, lab, or authorized penetration testing purposes only**. Do not deploy against systems without explicit permission.

---

## Repository Structure

```
.
├── README.md               # This file
├── setup.sh                # Main installer/setup script
├── docs/                   # Documentation for each component
├── tier1/                  # Tier 1: Modem / Router / VPN setup scripts
├── tier2/                  # Tier 2: Redirector & proxy nodes (e.g., Pi Zero 2)
├── tier3/                  # Tier 3: Lab C2 servers / Avaota SBC / Raspberry Pi 4/5
├── configs/                # nginx, socat, systemd, VPN, firewall configs
├── scripts/                # Helper scripts / automation
└── future\_components/      # Placeholder for expansion (C2 orchestration, logging, etc.)
```

---

## Project Goals

- Build a **modular, portable field kit** for lab testing and authorized engagements.  
- Enable **lightweight redirector deployment** on low-power SBCs (Pi Zero 2).  
- Support **ephemeral C2 staging** for safe experimentation.  
- Maintain **scalable architecture** for upgrading to Avaota SBC, Pi 4/5, or other hardware.  
- Provide scripts and automation for **repeatable deployments**.

---

## Tier Overview

### Tier 1: Network / Modem Layer
- Purpose: Provide connectivity for field kit without exposing your home/business network.  
- Components:
  - 4G/5G modem or MiFi device (e.g., RM500U + USB3 enclosure, GL-E750V2 Mudi V2)
  - Travel router (optional switch for multiple wired devices)
  - VPN concentrator for secure lab or field routing
- Scripts/configs in: `tier1/`

---

### Tier 2: Redirector Layer
- Purpose: Forward and proxy C2 traffic to lab or field C2 servers.  
- Hardware: Raspberry Pi Zero 2 W (or similar SBC)  
- Responsibilities:
  - Reverse proxy HTTP/S connections
  - TCP/UDP forwarding (socat, haproxy)
- Scripts/configs in: `tier2/`

---

### Tier 3: Lab / Field C2 Server
- Purpose: Host C2 infrastructure for testing agents, exfil, and ephemeral staging.  
- Hardware: Avaota SBC, Raspberry Pi 4/5, or other powerful SBC  
- Responsibilities:
  - Lab C2 for ephemeral operations
  - Logging and loot collection
  - Optional containerized stacks for portability
- Scripts/configs in: `tier3/`

---

## Current Components

- `setup.sh`: Main installer for Pi Zero 2 redirector / lab setup
- Systemd units for socat / nginx forwarding
- Minimal firewall (UFW) configuration
- TLS setup (Certbot) for HTTPS proxy

---

## Planned / Future Components

- Full field kit orchestration scripts  
- VPN + multi-network failover automation  
- Containerized redirector and C2 stacks for Avaota SBC / Pi 4/5  
- Logging and external storage support  
- Modular scripts for Tier 1, Tier 2, Tier 3 coordination  

---

## Usage

### Quickstart Lab Setup
1. Flash minimal OS (Raspberry Pi OS Lite / Ubuntu Server minimal) on your Pi Zero 2.  
2. Clone this repository:
```bash
git clone https://github.com/knight-scott/field-kit.git
cd field-kit
```

3. Run the setup script:

```bash
sudo bash setup.sh
```

4. Test redirector with lab C2 endpoints.

---

### Deployment Notes

* Each tier is **modular**; you can deploy only Tier 2 redirector or full Tier 1‑3 stack.
* Use ephemeral OS images or SD card backups for recovery.
* Always secure exposed ports and consider VPNs for field operations.

---

## Security Notes

* Only expose necessary ports for lab or field operations.
* Rotate ephemeral Pi images between sessions.
* Harden SSH access; use key-based authentication.
* Use external storage for logging or agent exfil data to reduce SD card wear.

---

## Contributing

* Add new scripts to `scripts/`
* Add configurations to `configs/`
* Follow **modular, safe practices** — each tier should remain independent where possible.
* Document changes in `docs/`

---

