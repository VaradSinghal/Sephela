---
title: Accessibility service abuse (T1417.001, T1626)
kind: technique
trust: vendor
source: MITRE ATT&CK Mobile — Input Capture / Abuse Elevation Control Mechanism
mitre: [T1417.001, T1626, T1517]
owasp_mobile: [M1, M8]
tags: [accessibility, keylogging, permission-escalation, overlay]
---

# Accessibility service abuse

Android's accessibility framework exists so assistive software can read screen
content and act on the user's behalf. Both capabilities are exactly what a
credential thief needs, and the framework grants them across application
boundaries. Accessibility abuse is consequently the single most powerful technique
available to Android banking malware.

## What the permission grants

A bound accessibility service can:

- receive events describing the content of any window, including text typed into
  other apps (`TYPE_VIEW_TEXT_CHANGED`) — a cross-app keylogger;
- read the full view hierarchy of the foreground app, including text nodes that
  contain balances, account numbers, and one-time passcodes;
- perform gestures and clicks (`performGlobalAction`, `ACTION_CLICK`) — which lets
  it approve system permission dialogs on its own behalf;
- detect which app is in the foreground, enabling precisely-timed overlays.

## Why it is a permission-escalation primitive

`BIND_ACCESSIBILITY_SERVICE` cannot be granted silently — the user must enable it
in Settings. Malware therefore invests heavily in coercion: a full-screen prompt
that reappears until enabled, a fake "Google Play Protect" or "enable to continue"
dialog, or an overlay covering the Settings toggle's warning text.

Once enabled, the service can grant subsequent runtime permissions by finding and
tapping the "Allow" button. The practical consequence for analysis: **a small
declared-permission set does not imply low capability** if an accessibility
service is present. The manifest understates what the app can do.

## Detection signals

Strong signals, in rough order of confidence:

1. `BIND_ACCESSIBILITY_SERVICE` in the manifest on an app with no plausible
   accessibility purpose.
2. An `accessibilityservice` meta-data resource declaring
   `canRetrieveWindowContent="true"` together with `typeAllMask` event filtering.
3. Accessibility event handling co-located with string obfuscation, reflection, or
   dynamic class loading.
4. A service that reacts to `TYPE_WINDOW_STATE_CHANGED` by comparing the package
   name against a list — the foreground-app detection that precedes an overlay.
5. Navigation away from `com.android.settings` screens, i.e. uninstall prevention.

## Legitimate uses that must not be flagged alone

Screen readers, password managers (autofill predates the Autofill Framework on
older API levels), remote-support tools, and automation utilities all legitimately
bind accessibility services. The permission on its own is not a finding. It becomes
one in combination with credential-relevant targets, overlays, SMS access,
obfuscation, or C2 communication.
