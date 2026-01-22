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
```
### Rule 2: Track Legitimate OCPP Session Start
```snort
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
```
### Rule 3: Detect Rogue STOP Command
```snort
alert tcp any any -> any 56284 (
  msg:"OCPP session STOP received too early - possible rogue control signal";
  flow:to_server,established;
  content:"stop";
  nocase;
  flowbits:isset,ocpp_session_started;
  sid:1000010;
  rev:1;
)
```
## Detection Logic
A legitimate charging session must first observe a START message.

A STOP message arriving outside the expected session lifecycle triggers an alert.

This approach detects protocol-level misuse rather than malformed packets.

## How to Run (High-Level)
Open MATLAB and verify the Simulink model loads:
```code
simulink/G2V.slx
```
Run MATLAB initialization scripts:
```code
matlab/init_G2V.m
```
Start Python OCPP components (example order):

Central Management System (CMS)

Charging Point (CP)

Start Snort with custom rules:
```code
snort -c snort/config/snort.conf -i <interface> -A alert_fast
```
Trigger rogue behavior (optional):

Run scripts in src/rogue/

Validate detection using Snort alerts and logs.

## What This Project Demonstrates
Exploitation of OCPP control-plane trust assumptions

Impact of rogue STOP commands on EV charging CPS

Detection of logic-level protocol attacks using Snort flowbits

Integration of cyber attack detection with a Simulink-based power system model

## Disclaimer
This repository is intended for educational and research purposes only.
All experiments should be conducted in controlled environments where you have explicit authorization to generate and inspect network traffic.

## References
1. (Project Resource) IEC61850-to-OCPP-and-SIMULINK GitHub Repository (Referenced as
a basis for cyber implementation concepts).
2. Alcaraz, C., Lopez, J., & Wolthusen, S. (2017). OCPP Protocol: Security Threats and
Challenges. IEEE Transactions on Smart Grid, 8(5), 2452-2459. doi:
10.1109/TSG.2017.2669647.
3. Carlson, R. B., Rohde, K. W., Crepeau, M. J., Salinas, S. C., Cook, S. E., & Medam, A.
(2023). Consequence-Driven Cybersecurity for High-Power Electric Vehicle Charging
Infrastructure. SAE Technical Paper Series. doi: 10.4271/2023-01-0047. Also available as:
Idaho National Laboratory, Technical Report, April 2023. [Online]. http://www.inl.gov.
4. Cumplido, J., Alcaraz, C., & Lopez, J. (2022). Collaborative anomaly detection system for
charging stations. In European Symposium on Research in Computer Security
(pp. 716–736). Springer.
5. Garofalaki, Z., Kosmanos, D., Moschoyiannis, S., Kallergis, D., & Douligeris, C. (2022).
Electric Vehicle Charging: A Survey on the Security Issues and Challenges of the Open
Charge Point Protocol (OCPP). IEEE Communications Surveys & Tutorials, 24(3), 1-1. doi:
10.1109/COMST.2022.3184448.
6. Hamdare, S., Kaiwartya, O., Aljaidi, M., Jugran, M., Cao, Y., Kumar, S., Mahmud, M.,
Brown, D., & Lloret, J. (2023). Cybersecurity risk analysis of electric vehicles charging
stations. Sensors, 23(15), 6716.
7. Li, Y., & Jenn, A. (2024). Impact of electric vehicle charging demand on power distribution
grid congestion. Proceedings of the National Academy of Sciences, 121(18), e2317599121.
doi: 10.1073/pnas.2317599121.
8. Open Charge Alliance. (n.d.). Protocols. Retrieved from
https://www.openchargealliance.org/protocols.
9. Z. Jiang, H. Tian, M. J. et al “Analysis of electric vehicle charging impact on the electric
power grid: Based on smart grid regional demonstration project — Los Angeles,” in Proc.
2016 IEEE PES Transmission and Distribution Conf. Expo., Dallas, TX, USA, 2016,
10. The Snort Team. (n.d.). Snort - Network Intrusion Detection & Prevention System.
Retrieved from https://www.snort.org/
11. Acharya, S., Dvorkin, Y., Pandi, H., & Karri, R. (2020). Cybersecurity of Smart Electric
Vehicle Charging: A Power Grid Perspective. IEEE Access, 8, 214434-214453. doi:
10.1109/ACCESS.2020.3041074.
12. NESCOR Technical Working Group 1, “Electric Sector Failure Scenarios and Impact
Analyses,” Version 1.0, Electric Power Research Institute (EPRI), Sep. 2013. [Online].
Available:https://smartgrid.epri.com/doc/NESCOR%20failure%20scenarios09-13%20finalc
.pdf
