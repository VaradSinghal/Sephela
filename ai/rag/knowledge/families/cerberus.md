---
title: Cerberus Banking Trojan
kind: malware_family
trust: curated
source: internal:threat-research
families: [cerberus, alien]
mitre: [T1417.001, T1626, T1437]
tags: [banking, overlay, rat]
---

# Cerberus Banking Trojan

Cerberus is a sophisticated Android banking trojan that heavily abuses the Android Accessibility Service to perform its malicious actions. Once the user grants Accessibility permissions, Cerberus uses them to grant itself additional permissions (like SMS reading and Device Admin) without user interaction.

## Key Behaviors
1. **Overlay Attacks**: It detects when a targeted banking application is launched and immediately draws a fake login screen over it to harvest credentials.
2. **SMS Interception**: It intercepts inbound SMS messages to steal Two-Factor Authentication (2FA) codes.
3. **Keylogging**: It logs keystrokes using Accessibility events to capture passwords and PINs.

## Detection Engineering
Look for applications requesting BIND_ACCESSIBILITY_SERVICE alongside SYSTEM_ALERT_WINDOW. Cerberus often disguises itself as a Flash Player update or a system utility.
