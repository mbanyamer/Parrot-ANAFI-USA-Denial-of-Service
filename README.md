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
