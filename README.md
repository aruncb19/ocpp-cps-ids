# OCPP CPS IDS Project (Simulink + Python + Snort)

This repository contains a cyber-physical systems (CPS) security project that studies **control-plane attacks on EV charging infrastructure** using the Open Charge Point Protocol (OCPP), and their detection using **Snort IDS**.

The project integrates:
- a MATLAB/Simulink-based EV power model (G2V / V2G),
- Python-based OCPP message flow components (Charging Point and Central Management System),
- and Snort IDS rules to detect **rogue control signal attacks**.

---

## Project Overview

EV charging systems rely on OCPP to exchange control messages such as `START` and `STOP` between Charging Points (CPs) and a Central Management System (CMS).  
This project demonstrates how **unauthorized control messages**—even when syntactically valid—can disrupt CPS operation, and how **protocol-aware IDS rules** can be used to detect such attacks.

The focus is on **logic-level attacks**, not malformed packets.

---

## My Contribution (Security / IDS)

My primary contribution focused on **attacking and defending the OCPP control channel**.

### Attack Scenarios Implemented

- **Rogue STOP attack**  
  Injected unauthorized `STOP` commands to prematurely terminate an active charging session.

- **Client ID spoofing**  
  Spoofed a legitimate Charging Point identifier to impersonate an authorized client and issue malicious control commands.

These attacks target the **control signal path** between CP and CMS, demonstrating how weak trust assumptions or insufficient authentication can be exploited in CPS environments.

### Detection Using Snort IDS

- Designed and implemented **Snort rules** to detect malicious OCPP control behavior.
- Used **flowbits** to track session state and distinguish legitimate session lifecycles from rogue STOP commands.
- Validated detection by correlating Snort alerts with injected rogue traffic.

This work demonstrates **protocol-aware intrusion detection**, focusing on **semantic misuse of control messages** rather than packet anomalies.

---

## Teammate Contribution (EV / Simulink)

- Designed and validated the MATLAB/Simulink EV power model (G2V / V2G).
- Implemented MATLAB initialization and runtime scripts.
- Managed CPS-side integration between Simulink and Python orchestration.

---

## Repository Structure

ocpp-cps-project/
├── src/
│ ├── cms/ # Central System-side Python scripts
│ ├── cp/ # Charging Point-side Python scripts
│ ├── rogue/ # Rogue behavior / attack scripts
│ └── tests/ # Test harness and validation scripts
├── matlab/ # MATLAB initialization and helper scripts
├── simulink/ # Simulink EV model (.slx)
├── snort/
│ ├── rules/ # Custom Snort IDS rules
│ └── config/ # Snort configuration (optional)
└── README.md



---

## Snort IDS Rules (OCPP Control Attacks)

The following Snort rules were used to detect rogue OCPP control behavior on the CMS port (**56284**).

### Rule 1: Detect CP → CMS OCPP Traffic
```snort
alert tcp any any -> any 56284 (
  msg:"OCPP CP-CMS traffic detected";
  flow:to_server,established;
  content:"stop";
  nocase;
  sid:1000004;
  rev:1;
)
Rule 2: Track Legitimate OCPP Session Start

alert tcp any any -> any 56284 (
  msg:"OCPP session started";
  flow:to_server,established;
  content:"start";
  nocase;
  flowbits:set,ocpp_session_started;
  flowbits:timeout,30;
  sid:1000009;
  rev:1;
)
Rule 3: Detect Rogue STOP Command

alert tcp any any -> any 56284 (
  msg:"OCPP session STOP received too early - possible rogue control signal";
  flow:to_server,established;
  content:"stop";
  nocase;
  flowbits:isset,ocpp_session_started;
  sid:1000010;
  rev:1;
)
Detection Logic
A legitimate charging session must first observe a START message.

A STOP message arriving outside the expected session lifecycle triggers an alert.

This approach detects protocol-level misuse rather than malformed packets.

How to Run (High-Level)
Open MATLAB and verify the Simulink model loads:


simulink/G2V.slx
Run MATLAB initialization scripts:


matlab/init_G2V.m
Start Python OCPP components (example order):

Central Management System (CMS)

Charging Point (CP)

Start Snort with custom rules:

snort -c snort/config/snort.conf -i <interface> -A alert_fast
Trigger rogue behavior (optional):

Run scripts in src/rogue/

Validate detection using Snort alerts and logs.

What This Project Demonstrates
Exploitation of OCPP control-plane trust assumptions

Impact of rogue STOP commands on EV charging CPS

Detection of logic-level protocol attacks using Snort flowbits

Integration of cyber attack detection with a Simulink-based power system model

Disclaimer
This repository is intended for educational and research purposes only.
All experiments should be conducted in controlled environments where you have explicit authorization to generate and inspect network traffic.