# The Greenholt Phish — TryHackMe

**Room:** [The Greenholt Phish](https://tryhackme.com/room/greenholtphish)
**Path:** SOC Level 1 → Phishing Analysis
**Date completed:** July 2026

## Scenario

A Sales Executive at Greenholt PLC received an email he didn't expect from a customer. The goal was to analyze the email headers, attachment, and infrastructure to determine whether the message was legitimate or malicious.

## Email Header Analysis

The email claimed to originate from `mutawamarine.com`, but analysis of the SMTP header chain revealed spoofing.

**Key headers:**

```
Return-Path: <info@mutawamarine.com>
Received-SPF: fail (domain of mutawamarine.com does not designate x.x.x.x as permitted sender)
Authentication-Results: spf=fail smtp.mailfrom=mutawamarine.com; dmarc=unknown
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810 helo=mutawamarine.com)
    by sub.redacted.com with esmtp (Exim 4.80)
From: "Mr. James Jackson" <info@mutawamarine.com>
Reply-To: "Mr. James Jackson" <info.mutawamarine@mail.com>
Subject: webmaster@redacted.org your: Transfer Reference Number:(09674321)
```

**Finding:** The message claimed to be from `mutawamarine.com` but was actually relayed from a Hostwinds-hosted server (`hostwindsdns.com`), unrelated to the legitimate domain. The `HELO` value was spoofed to impersonate the sender domain — a classic sender spoofing technique.

## Sending IP Investigation

| Field | Value |
|---|---|
| Originating IP | `192.119.71.157` |
| ASN | AS54290 — Hostwinds LLC |
| Registered Org (current WHOIS) | HostPapa (HOSTP-7) |
| Hosting type | Generic shared/VPS hosting (not a Microsoft/Outlook mail server) |

**Note:** WHOIS `Organization` field showed HostPapa rather than Hostwinds, despite the hostname (`hostwindsdns.com`) and ASN both pointing to Hostwinds. This is explained by a corporate relationship/administrative update between the two hosting providers over time — WHOIS records reflect current registration data, not necessarily the state at the time of the incident (2020). Both the ASN owner and the reverse DNS hostname consistently point to Hostwinds infrastructure.

## SPF / DMARC Verification

Verified independently via DNS TXT lookup (`nslookup -type=TXT`) against the legitimate domain:

```
SPF:   v=spf1 include:spf.protection.outlook.com -all
DMARC: v=DMARC1; p=quarantine; fo=1
```

**Analysis:**
- The legitimate SPF record authorizes **only** Microsoft Outlook/Office 365 servers to send mail on behalf of `mutawamarine.com`, with a hard-fail policy (`-all`) for anything else.
- The sending IP (Hostwinds/HostPapa infrastructure) is not part of that authorized list — confirming the `Received-SPF: fail` result and the spoofing conclusion.
- DMARC policy is `p=quarantine`, meaning messages failing SPF/DKIM should be routed to spam rather than delivered to the inbox — highlighting that DMARC policy alone does not guarantee rejection, since final message handling also depends on the receiving mail server's enforcement and filtering configuration.

## Attachment Analysis

- The email attachment had a `.cab` file extension, but VirusTotal identified the true file type as a **RAR archive** based on file signature (magic bytes), not the declared extension.
- This is a common evasion technique: renaming a file's extension does not alter its underlying binary content. Analysis tools identify true file type via magic numbers (e.g., RAR: `52 61 72 21`, ZIP: `50 4B`, EXE: `4D 5A`), independent of the filename.

## MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Malicious archive disguised with a mismatched extension |
| Spoofing | (supporting) | SPF/HELO spoofing of `mutawamarine.com` |

## IOCs Summary

*IOCs below are defanged (`[.]`/`[at]`) to prevent accidental clicks.*

| Type | Value |
|---|---|
| Spoofed domain | mutawamarine[.]com |
| Sending IP | 192.119.71[.]157 |
| Sending infrastructure | hwsrv-737338[.]hostwindsdns[.]com (Hostwinds/HostPapa) |
| Reply-To | info.mutawamarine[at]mail[.]com |
| Attachment | Disguised `.cab` (true type: RAR) |

## Conclusion

The email is a confirmed phishing attempt using domain spoofing and a disguised malicious attachment. SPF failure and infrastructure mismatch provide strong technical evidence independent of the email content itself.
