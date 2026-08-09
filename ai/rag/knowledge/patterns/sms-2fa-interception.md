---
title: SMS and 2FA interception pattern
kind: behavior_pattern
trust: curated
source: internal:threat-research
families: [cerberus, flubot, anatsa, hydra]
mitre: [T1636.004, T1582, T1517]
owasp_mobile: [M1, M2]
tags: [sms, otp, 2fa, notification-listener, smishing]
---

# SMS and 2FA interception pattern

Stolen credentials alone rarely complete a fraudulent transfer; the second factor
does. Interception of SMS one-time passcodes is therefore a near-universal
component of Android banking fraud, and its presence alongside credential theft
raises severity substantially — together they represent a complete account
takeover capability rather than a partial one.

## SMS path

- `RECEIVE_SMS` with a `BroadcastReceiver` on `android.provider.Telephony.SMS_RECEIVED`,
  usually at a high `android:priority` so the malicious receiver runs first.
- Calling `abortBroadcast()` suppresses delivery to the default messaging app, so
  the victim never sees the code. A receiver that both reads and aborts is
  conclusive.
- `READ_SMS` additionally allows harvesting the historic message store, which
  yields previously delivered codes and bank notification history.
- `SEND_SMS` supports premium-rate fraud and, in worm-capable families, self-
  propagation to the victim's contacts.

## Notification path

App-based authenticators and push-based confirmations do not use SMS, so malware
also requests `BIND_NOTIFICATION_LISTENER_SERVICE`. A notification listener reads
the content of every notification on the device, including authenticator codes and
transaction confirmations, and can dismiss them to hide the fraud from the victim.
This path requires no SMS permission at all and is easy to miss when triage focuses
on SMS.

## Default-SMS-handler path

Some families request to become the default SMS application. That grants full
message access without the individual SMS permissions, and looks superficially
legitimate for an app presenting itself as a messaging utility.

## Analysis signals

- Any SMS permission on an app whose stated purpose does not involve messaging.
- A high-priority SMS receiver, especially combined with `abortBroadcast`.
- Regular-expression matching over message bodies for digit sequences — OTP
  extraction.
- Notification-listener service declared alongside credential-theft indicators.
- Immediate network transmission following message receipt: the exfiltration leg.

## Severity interaction

Treat SMS/notification interception as an *amplifier* rather than an independent
finding. On its own it may be a legitimate messaging or automation feature. Present
alongside overlay phishing, accessibility abuse, or a known-malicious C2 endpoint,
it converts a suspicious app into a demonstrated account-takeover tool.
