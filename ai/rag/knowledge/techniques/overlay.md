---
title: Android Overlay Attacks
kind: technique
trust: curated
source: internal:threat-research
families: [cerberus, anubis, hydra]
mitre: [T1417.001]
tags: [ui_redress, credentials]
---

# Android Overlay Attacks (T1417.001)

An overlay attack occurs when a malicious application draws a window on top of a legitimate application. In Android, this is typically achieved using the SYSTEM_ALERT_WINDOW permission, which allows an app to draw over other apps.

## Execution
Malware monitors the foreground application (often via Accessibility Services or UsageStatsManager). When a targeted app (like a banking app) is launched, the malware rapidly launches an Activity or Service that draws a transparent or opaque view over the screen, presenting a fake login prompt.

## Mitigation
Android 10+ introduced stricter controls on starting activities from the background, and modern banking apps use FLAG_SECURE to prevent screenshots, though this does not always stop overlay drawing.
