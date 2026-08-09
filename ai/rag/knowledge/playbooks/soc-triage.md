---
title: SOC triage playbook for a suspected fraudulent banking APK
kind: playbook
trust: curated
source: internal:soc-playbooks
tags: [triage, escalation, response, banking]
owasp_mobile: [M1]
---

# SOC triage playbook — suspected fraudulent banking APK

Guidance for the analyst receiving a Sephela report. Written for a bank's fraud
and security operations context, where the operative questions are "are our
customers being targeted right now" and "what do we take down".

## 1. Establish whether the sample impersonates us

Check the package name, application label, icon, and any overlay assets against
the institution's own apps. A near-miss package name (`com.bank.mobile.secure`
against a real `com.bank.mobile`) or a bundled clone of the login screen means the
institution is a named target, which raises priority regardless of the numeric risk
score.

## 2. Determine capability, not just intent

Confirm which of the following are evidenced, since together they constitute
account takeover:

- credential capture (overlay, WebView phishing, keylogging);
- second-factor interception (SMS receiver, notification listener);
- remote control or transfer automation (accessibility gestures, RAT commands).

Two of the three is an active fraud tool. All three warrants immediate escalation.

## 3. Extract and action the indicators

- **C2 endpoints** → submit for blocking at the network perimeter and to the
  takedown provider; share with the national CERT and sector ISAC.
- **Distribution URLs** → request takedown of the hosting site; report to Google
  Safe Browsing and, where a store listing exists, to Play Protect.
- **Sample hash** → submit to industry sharing platforms so peers benefit.
- **Signing certificate** → pivot on it. Fraud campaigns commonly reuse one signing
  key across many samples, so the certificate finds the rest of the campaign faster
  than any other indicator.

## 4. Assess customer exposure

Correlate the target list with the institution's own customer base, and search
authentication and transaction logs for the sample's user-agent, device
fingerprints, or the source addresses of its C2. Where the malware has been active,
look for enrolment of new devices and changes to notification settings.

## 5. Escalate

Escalate to fraud operations when the sample targets the institution, has
functioning C2, and shows both credential and second-factor capture. Include in the
handover: the family attribution and its confidence, the specific evidence for each
capability, the indicator list, and explicitly what remains unknown — a sandbox run
suppressed by anti-analysis checks is missing information, not evidence of
harmlessness.

## 6. Record what the analysis could not determine

Note dynamic-analysis coverage gaps, unresolved obfuscation, and any enrichment
that was rate-limited or unavailable. An incomplete analysis presented as complete
is the failure mode that costs the most later.
