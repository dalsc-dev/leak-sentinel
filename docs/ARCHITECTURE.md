# Architecture & Design Overview

LeakSentinel is structured into 5 decoupled audit modules:
1. DNS Auditor (`src/dns-auditor.js`): Inspects resolver chains, unencrypted gateways, and SMHNR multi-homing.
2. WebRTC Auditor (`src/webrtc-auditor.js`): Analyzes ICE candidate SDP strings for STUN reflexive public IPs and IPv6 bypass.
3. LAN Auditor (`src/lan-auditor.js`): Audits non-loopback bindings on sensitive developer ports.
4. HTTP Auditor (`src/http-auditor.js`): Detects proxy header forwarding and high-entropy client hints.
5. Fingerprint Auditor (`src/fingerprint-auditor.js`): Measures unmasked hardware parameters.
