# Parrot ANAFI USA - MAVLink MISSION_COUNT Invalid Type DoS (CVE-2024-33844)

![Parrot ANAFI USA](https://www.parrot.com/sites/default/files/2021-06/anafi-usa-hero.jpg)

**Exploit Title:** Parrot ANAFI USA - MAVLink MISSION_COUNT Invalid Type Denial of Service (DoS)  
**Date:** 2025-11-03  
**Author:** Mohammed Idrees Banyamer  
**Country:** Jordan  
**Instagram:** [@banyamer_security](https://instagram.com/banyamer_security)  
**GitHub:** [mbanyamer](https://github.com/mbanyamer)  
**Vendor Homepage:** https://www.parrot.com  
**Product Page:** https://www.parrot.com/us/drones/anafi-usa  
**Affected Firmware:** `< v1.10.5`  
**Tested on:** ANAFI USA (Wi-Fi & Skycontroller – UDP/TCP MAVLink)  
**CVE:** CVE-2024-33844  
**Category:** Drone / UAV  
**Platform:** Hardware / Embedded  

---

## Vulnerability Overview

The Parrot ANAFI USA drone does **not properly validate** the `mission_type` field in incoming MAVLink `MISSION_COUNT` messages.

Sending a `MISSION_COUNT` message with an **invalid `mission_type` value (e.g., 17)** causes a **null pointer dereference** in the internal function `mavlink_itf_reset_mission_data()`, resulting in:

- Immediate crash of the `control` service  
- Full disconnection of the Ground Control Station (GCS)  
- Complete loss of telemetry and control (DoS)  

This enhanced PoC implements a **reliable, persistent, and multi-protocol** attack with automatic reconnect & retry logic.

---

## Requirements

```bash
pip install pymavlink


### Options

| Option        | Description                              | Default       |
|---------------|------------------------------------------|---------------|
| `--ip`        | Drone IP address                         | 192.168.42.1  |
| `--port`      | MAVLink port                             | 14550         |
| `--protocol`  | `udp` or `tcp`                           | udp           |
| `--burst`     | Number of malicious packets per burst     | 10            |
| `--delay`     | Delay between packets (seconds)          | 0.1           |
| `--persistent`| Infinite loop – reconnect & re-attack    | off           |

---

## Example Output (Successful DoS)

```log
12:34:56 [INFO] Attempting UDP connection to 192.168.42.1:14550...
12:34:57 [INFO] Connected! System ID: 1, Component ID: 1
12:34:57 [INFO] Launching DoS burst: 25 malformed MISSION_COUNT messages...
12:34:59 [CRITICAL] No heartbeat received - DoS SUCCESSFUL!
12:35:00 [CRITICAL] Exploit successful - drone is down!
