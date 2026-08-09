---
title: Cerberus / Alien banking trojan family
kind: malware_family
trust: curated
source: internal:threat-research
families: [cerberus, alien, ermac]
mitre: [T1417.001, T1417.002, T1636.004, T1626, T1476]
owasp_mobile: [M1, M8]
tags: [banking, overlay, accessibility, sms-interception, rat]
---

# Cerberus / Alien banking trojan family

Cerberus is an Android banking trojan first offered as malware-as-a-service in
2019. After its source leak, it spawned the Alien and ERMAC lineages, which share
most of its implementation and nearly all of its observable behaviour. Treat the
three as one behavioural cluster during triage.

## Distribution and disguise

Samples masquerade as utility applications — Flash Player updates, currency
converters, delivery trackers, or government/tax portals localized to the target
market. The dropper carries little malicious logic itself and fetches the real
payload after install, so a static-only view of the dropper often looks benign
apart from an unusual install-packages permission.

## Accessibility service abuse

The defining behaviour. The app requests
`android.permission.BIND_ACCESSIBILITY_SERVICE` and drives the user to enable it
through a persistent full-screen prompt. With the service bound, it:

- reads on-screen text from other applications, including banking apps, to
  identify which institution the victim is using;
- grants itself further permissions by locating and tapping system dialog buttons,
  which is why a Cerberus sample often needs to declare fewer permissions in the
  manifest than its behaviour implies;
- keylogs by observing view-changed accessibility events;
- suppresses uninstall attempts by detecting the settings screen and navigating
  away from it.

An accessibility-service declaration combined with a request-install-packages or
system-alert-window permission is the strongest single manifest indicator of this
family.

## Overlay credential theft

The trojan downloads HTML/webview "injects" — pixel-accurate clones of specific
banking app login screens — and draws them over the legitimate app when it
detects that app in the foreground. Target lists are fetched from the command and
control server, so the injects present in a sample identify the campaign's target
institutions. Overlays are drawn via `SYSTEM_ALERT_WINDOW` or, in later variants,
via accessibility-driven activity launching that avoids the overlay permission
entirely.

## SMS and 2FA interception

`RECEIVE_SMS` / `READ_SMS` with a high-priority SMS broadcast receiver lets the
trojan read one-time passcodes and forward them to the operator, then optionally
abort the broadcast so the victim never sees the message. Notification-listener
access is used for the same purpose against app-based authenticators.

## Command and control

HTTP(S) POST to PHP endpoints, frequently on bare IP addresses or short-lived
low-cost TLDs. Payloads are commonly AES-encrypted then base64 or RC4-obfuscated,
with the key embedded in the DEX or derived from a hard-coded seed. Cerberus also
retrieves fallback C2 addresses from Twitter/Telegram profile text, so an absence
of hard-coded C2 endpoints does not rule the family out.

## Anti-analysis

Checks for emulator artefacts (build fingerprints, sensor absence, telephony
values), uses the accelerometer step counter as a "is this a real phone" heuristic,
and delays payload activation for hours or until a step threshold is met. This is
the usual reason a dynamic sandbox run of a real Cerberus sample records little
activity.

## Discriminators from lookalike families

- Anatsa/TeaBot: also accessibility-driven, but stages its payload through a
  dedicated dropper on the Play Store and uses a distinctive
  `getSystemService`-based screen-capture path.
- Hydra: overlaps heavily on overlays but historically requests device-admin
  rather than relying purely on accessibility.
- FluBot: SMS-worm distribution (delivery-notification smishing) is its signature;
  Cerberus does not self-propagate over SMS.
