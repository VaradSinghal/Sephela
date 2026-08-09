---
title: Overlay credential theft pattern
kind: behavior_pattern
trust: curated
source: internal:threat-research
families: [cerberus, hydra, anatsa, ermac, octo]
mitre: [T1417.002, T1516, T1414]
owasp_mobile: [M1, M4]
tags: [overlay, phishing, system-alert-window, webview, credential-theft]
---

# Overlay credential theft pattern

The dominant credential-theft mechanism in Android banking fraud. The malicious
app draws a convincing replica of a target bank's login screen on top of the real
app at the moment the victim opens it. The victim types real credentials into the
attacker's view.

## Mechanics

1. **Target detection.** The app determines which application is in the
   foreground, via an accessibility service (`TYPE_WINDOW_STATE_CHANGED`), the
   `UsageStatsManager`, or — on older API levels — `getRunningTasks`.
2. **Inject selection.** The foreground package name is matched against a target
   list. The list is usually downloaded from C2 rather than embedded, so it can be
   retargeted without redistributing the APK.
3. **Overlay presentation.** A WebView loads attacker-supplied HTML/CSS in a window
   of type `TYPE_APPLICATION_OVERLAY` (requires `SYSTEM_ALERT_WINDOW`), or a
   transparent full-screen activity is launched via accessibility to avoid needing
   the overlay permission at all.
4. **Exfiltration.** Captured fields are POSTed to C2, frequently alongside the
   device model, locale, and installed-app inventory used to prioritize victims.

## Analysis signals

- `SYSTEM_ALERT_WINDOW` in an app with no legitimate floating-UI purpose.
- A WebView with `setJavaScriptEnabled(true)` plus `addJavascriptInterface`, loading
  content from a remote origin or from a locally decrypted asset.
- HTML/CSS/JS assets in `assets/` or `res/raw/` that reference bank names, or that
  are encrypted blobs of similar size and shape.
- A package-name list in code, resources, or a decrypted string table — especially
  one containing banking or wallet package names.
- `QUERY_ALL_PACKAGES` or repeated `getInstalledPackages` calls: the app is
  enumerating which banks the victim uses.

## Evolution worth knowing

Android 10+ restricted background activity launches and made overlay abuse more
visible, so newer families shifted to accessibility-driven activity launching and
to full-screen "phishing activities" triggered from a foreground service with a
persistent notification. The absence of `SYSTEM_ALERT_WINDOW` therefore does not
rule out overlay behaviour in a modern sample; check for accessibility-driven
launches instead.

## Distinguishing from legitimate overlays

Chat heads, screen recorders, blue-light filters, and accessibility magnifiers all
use overlay windows legitimately. The discriminator is *what the overlay contains
and when it appears*: a credential form shown in response to a specific
foreground package is unambiguous, whereas a persistent decorative overlay is not.
