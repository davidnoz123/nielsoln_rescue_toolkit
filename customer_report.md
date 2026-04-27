# Laptop Diagnostic Report

**Prepared by:** Nielsoln Rescue Toolkit  
**Date:** 27 April 2026  
**Machine:** ASUSTeK Computer Inc. F5GL 1.0
**Serial number:** NF1S8C05960013  
**BIOS date:** 11/20/2008  

---

## Overall Assessment

> ⚪ **REVIEW RECOMMENDED**

## Hardware

| Field | Value |
|---|---|
| Manufacturer | ASUSTeK Computer Inc. |
| Model | F5GL 1.0 |
| Serial number | NF1S8C05960013 |
| Form factor | laptop |
| BIOS date | 11/20/2008 |
| CPU | Intel(R) Pentium(R) Dual  CPU  T3400  @ 2.16GHz |
| CPU cores / threads | N/A / N/A |
| RAM | 3.6 GiB |

**Storage devices:**

| Device | Model | Size | Type |
|---|---|---|---|
| /dev/sda | ST9250320AS | 232.9 GB | HDD |
| /dev/sdb | OnlyDisk | 29.0 GB | HDD |
| /dev/sdc | OnlyDisk | 29.0 GB | HDD |

**Display adapters:**

- VGA compatible controller: NVIDIA Corporation MCP79 [GeForce 8200M G] (rev b1)

**Network adapters:**

- enp0s10 (forcedeth)
- wlp6s0 (ath9k)

## Disk Health

### /dev/sda — ST9250320AS

| | |
|---|---|
| SMART health | PASSED |
| Overall verdict | 🟡 **CAUTION** |
| Clone urgency | **soon** |
| Power On Hours | 2227 |

**Findings:**

- Spin_Retry_Count = 11 (ID 10)
- Command_Timeout = 1 (ID 188)

**Recommendation:** Drive shows warning signs. Plan a clone soon and monitor closely.

### /dev/sdb — OnlyDisk

| | |
|---|---|
| SMART health | ? |
| Overall verdict | ⚪ **?** |
| Clone urgency | **none** |

**Recommendation:** SMART data unavailable or inconclusive.

### /dev/sdc — OnlyDisk

| | |
|---|---|
| SMART health | ? |
| Overall verdict | ⚪ **?** |
| Clone urgency | **none** |

**Recommendation:** SMART data unavailable or inconclusive.

## Antivirus Scan

| | |
|---|---|
| Result | 🟢 **CLEAN** |
| Threats found | 0 |
| Files scanned | 0 |

## Windows Security — Logon Audit

| | |
|---|---|
| Verdict | 🟢 **CLEAN** |
| Failed logon attempts | 0 |
| Account lockouts | 0 |
| Password change events | 0 |
| Explicit credential logons | 7184 |
| Account management events | 0 |

**Notes:**

- No failed logon attempts found in the Security log.
- 7184 'logon with explicit credentials' event(s) — could be a scheduled task, cached credentials, or malware.

## Persistence / Autorun Analysis

| | |
|---|---|
| Total autorun entries | 239 |
| Suspicious | 0 |
| Clean | 239 |

> No suspicious autorun entries found.

## Windows Services

| | |
|---|---|
| Verdict | 🟡 **SUSPICIOUS** |
| Total registered | 441 |
| Auto-start (non-driver) | 75 |
| Third-party | 0 |
| Suspicious | 3 |

## Software Inventory

**71 applications found** on the Windows installation.

**Flagged items:**

| Name | Version | Publisher | Flags |
|---|---|---|---|
| Glary Utilities 2.29.0.1032 | 2.29.0.1032 | Glarysoft Ltd | legacy-install-date |
| Google Chrome | 49.0.2623.112 | Google Inc. | legacy-install-date |
| CyberLink Power2Go | 6.0.1924 | CyberLink Corp. | bloat, legacy-install-date |
| iPod for Windows 2005-10-12 | 4.3.0 | Apple Computer, Inc. | legacy-install-date |
| McAfee Security Scan Plus | 3.11.266.3 | McAfee, Inc. | bloat |
| Multimedia Card Reader | 1.01.0000.00 | N/A | legacy-install-date |
| ASUS Splendid Video Enhancement Technology | 1.02.0021 | ASUS | legacy-install-date |
| LightScribe System Software  1.14.17.1 | 1.14.17.1 | LightScribe | legacy-install-date |
| ASUS LifeFrame3 | 3.0.8 | ASUS | legacy-install-date |
| Google Toolbar for Internet Explorer | 7.5.8231.2252 | Google Inc. | suspicious, bloat |
| Java(TM) 6 Update 14 | 6.0.140 | Sun Microsystems, Inc. | legacy-publisher, legacy-install-date |
| Atheros Client Installation Program | 7.0 | Atheros | legacy-install-date |
| Express Gate | 0.8.6.0 | devicevm | legacy-install-date |
| Bing Bar | 7.3.132.0 | Microsoft Corporation | bloat |
| ATK Hotkey | 1.00.0034 | ATK | legacy-install-date |
| Cisco EAP-FAST Module | 2.1.6 | Cisco Systems, Inc. | legacy-install-date |
| ASUS InstantFun | 1.0.0015 | ASUS | legacy-install-date |
| ATKOSD2 | 6.64.1.8 | ATK | legacy-install-date |
| ASUS SmartLogon | 1.0.0005 | ASUS | legacy-install-date |
| Cisco PEAP Module | 1.0.13 | Cisco Systems, Inc. | legacy-install-date |
| Microsoft Visual C++ 2005 Redistributable | 8.0.61001 | Microsoft Corporation | legacy-install-date |
| Microsoft Visual C++ 2005 ATL Update kb973923 - x86 8.0.50727.4053 | 8.0.50727.4053 | Microsoft Corporation | legacy-install-date |
| Bonjour | 3.0.0.10 | Apple Inc. | legacy-install-date |
| Cisco LEAP Module | 1.0.12 | Cisco Systems, Inc. | legacy-install-date |
| Wireless Console 2 | 2.0.10 | ATK | legacy-install-date |
| MobileMe Control Panel | 3.1.8.0 | Apple Inc. | legacy-install-date |
| ASUS Power4Gear eXtreme | 1.0.19 | ASUS | legacy-install-date |
| iPodRip | 1.0.1.11 | Happy Hour Code, LLC. | legacy-install-date |
| Dolby Control Center | 2.0.0706 | Dolby | legacy-install-date |
| Spelling Dictionaries Support For Adobe Reader 8 | 8.0.0 | Adobe Systems | legacy-install-date |
| CyberLink LabelPrint | 2.0.2908 | CyberLink Corp. | bloat |
| Safari | 5.34.57.2 | Apple Inc. | legacy-install-date |
| ATK Generic Function Service | 1.00.0008 | ATK | legacy-install-date |
| ASUS Virtual Camera | 1.0.09 | asus | legacy-install-date |
| Realtek High Definition Audio Driver | 6.0.1.5683 | Realtek Semiconductor Corp. | legacy-install-date |

<details>
<summary>Full software list (click to expand)</summary>

| Name | Version | Publisher | Install date |
|---|---|---|---|
| Adobe Flash Player 10 ActiveX | 10.0.22.87 | Adobe Systems Incorporated | N/A |
| Adobe Flash Player 10 Plugin | 10.1.53.64 | Adobe Systems Incorporated | N/A |
| Adobe Reader X (10.1.16) | 10.1.16 | Adobe Systems Incorporated | 20151014 |
| Adobe Shockwave Player 11.5 | 11.5 | Adobe Systems, Inc. | N/A |
| Agere Systems HDA Modem | N/A | Agere Systems | N/A |
| Apple Application Support (32-bit) | 3.1.3 | Apple Inc. | 20161225 |
| Apple Mobile Device Support | 9.0.0.26 | Apple Inc. | 20161225 |
| Apple Software Update | 2.1.4.131 | Apple Inc. | 20161225 |
| ASUS InstantFun | 1.0.0015 | ASUS | 20081216 |
| ASUS LifeFrame3 | 3.0.8 | ASUS | 20081216 |
| ASUS Live Update | 2.5.6 | ASUS | 12-16-2008 |
| ASUS Power4Gear eXtreme | 1.0.19 | ASUS | 20081216 |
| ASUS SmartLogon | 1.0.0005 | ASUS | 20081216 |
| ASUS Splendid Video Enhancement Technology | 1.02.0021 | ASUS | 20081216 |
| ASUS Virtual Camera | 1.0.09 | asus | 20081216 |
| Asus_Camera_ScreenSaver | 2.0.0007 | ASUS | 2008/12/16 |
| Atheros Client Installation Program | 7.0 | Atheros | 20081216 |
| ATK Generic Function Service | 1.00.0008 | ATK | 20081216 |
| ATK Hotkey | 1.00.0034 | ATK | 20081216 |
| ATK Media | N/A | N/A | N/A |
| ATKOSD2 | 6.64.1.8 | ATK | 20081216 |
| Bing Bar | 7.3.132.0 | Microsoft Corporation | 20140503 |
| Bonjour | 3.0.0.10 | Apple Inc. | 20111021 |
| Cisco EAP-FAST Module | 2.1.6 | Cisco Systems, Inc. | 20081216 |
| Cisco LEAP Module | 1.0.12 | Cisco Systems, Inc. | 20081216 |
| Cisco PEAP Module | 1.0.13 | Cisco Systems, Inc. | 20081216 |
| Compatibility Pack for the 2007 Office system | 12.0.6612.1000 | Microsoft Corporation | 20161013 |
| CyberLink LabelPrint | 2.0.2908 | CyberLink Corp. | N/A |
| CyberLink Power2Go | 6.0.1924 | CyberLink Corp. | 20081216 |
| Dolby Control Center | 2.0.0706 | Dolby | 20081216 |
| Express Gate | 0.8.6.0 | devicevm | 20081216 |
| Glary Utilities 2.29.0.1032 | 2.29.0.1032 | Glarysoft Ltd | 20101028 |
| Google Chrome | 49.0.2623.112 | Google Inc. | 20100216 |
| Google Desktop | 5.9.1005.12335 | Google | N/A |
| Google Toolbar for Internet Explorer | 7.5.8231.2252 | Google Inc. | N/A |
| Hotfix for Microsoft .NET Framework 3.5 SP1 (KB953595) | 1 | Microsoft Corporation | N/A |
| Hotfix for Microsoft .NET Framework 3.5 SP1 (KB958484) | 1 | Microsoft Corporation | N/A |
| iCloud | 2.1.3.25 | Apple Inc. | 20141106 |
| iPod for Windows 2005-10-12 | 4.3.0 | Apple Computer, Inc. | 20090109 |
| iPodRip | 1.0.1.11 | Happy Hour Code, LLC. | 20090702 |
| iTunes | 12.1.3.6 | Apple Inc. | 20161225 |
| Java(TM) 6 Update 14 | 6.0.140 | Sun Microsystems, Inc. | 20090801 |
| LightScribe System Software  1.14.17.1 | 1.14.17.1 | LightScribe | 20081216 |
| McAfee Security Scan Plus | 3.11.266.3 | McAfee, Inc. | N/A |
| Microsoft .NET Framework 3.5 SP1 | N/A | Microsoft Corporation | N/A |
| Microsoft .NET Framework 4 Client Profile | 4.0.30319 | Microsoft Corporation | N/A |
| Microsoft Office File Validation Add-In | 14.0.5130.5003 | Microsoft Corporation | 20200629 |
| Microsoft Office Standard Edition 2003 | 11.0.8173.0 | Microsoft Corporation | 20170619 |
| Microsoft Visual C++ 2005 ATL Update kb973923 - x86 8.0.50727.4053 | 8.0.50727.4053 | Microsoft Corporation | 20090730 |
| Microsoft Visual C++ 2005 Redistributable | 8.0.61001 | Microsoft Corporation | 20110615 |
| MobileMe Control Panel | 3.1.8.0 | Apple Inc. | 20111124 |
| Multimedia Card Reader | 1.01.0000.00 | N/A | 20081216 |
| NB Probe | N/A | N/A | N/A |
| Norton 360 | 22.15.5.40 | Symantec Corporation | 20211223 |
| NVIDIA Drivers | N/A | N/A | N/A |
| PokerStars.net | N/A | PokerStars.net | Fri Jun 18 13:56:19 2010 |
| QuickTime 7 | 7.79.80.95 | Apple Inc. | 20200707 |
| Realtek High Definition Audio Driver | 6.0.1.5683 | Realtek Semiconductor Corp. | 20081216 |
| Safari | 5.34.57.2 | Apple Inc. | 20120603 |
| Security Update for Microsoft .NET Framework 3.5 SP1 (KB2416473) | 1 | Microsoft Corporation | N/A |
| Security Update for Microsoft .NET Framework 4 Client Profile (KB2446708) | 1 | Microsoft Corporation | N/A |
| Security Update for Microsoft .NET Framework 4 Client Profile (KB2478663) | 1 | Microsoft Corporation | N/A |
| Security Update for Microsoft .NET Framework 4 Client Profile (KB2518870) | 1 | Microsoft Corporation | N/A |
| Skype™ 7.0 | 7.0.102 | Skype Technologies S.A. | 20150703 |
| Spelling Dictionaries Support For Adobe Reader 8 | 8.0.0 | Adobe Systems | 20090407 |
| Synaptics Pointing Device Driver | 10.0.12.0 | Synaptics | N/A |
| Update for Microsoft .NET Framework 3.5 SP1 (KB963707) | 1 | Microsoft Corporation | N/A |
| USB 2.0 1.3M UVC WebCam | N/A | N/A | N/A |
| WinFlash | N/A | N/A | N/A |
| WinZip Driver Updater | 1.0.648.16469 | WinZip Computing, S.L. (WinZip Computing) | 20150201 |
| Wireless Console 2 | 2.0.10 | ATK | 20081216 |

</details>

## Thermal & Performance

| | |
|---|---|
| Verdict | ⚪ **WARM** |

**Notes:**

- No fan data available — fan monitoring may not be supported by this hardware
- CPU is frequency-throttled: 1015 MHz / 2167 MHz max — possible thermal event

## Upgrade Recommendation

## Recommended Next Steps

1. **Back up your data soon** — the hard drive has early warning signs of wear.
2. **Replace the hard drive with an SSD** — this will dramatically improve speed,
   reliability, and battery life. The machine will feel like new.
3. **Upgrade the operating system** — Windows Vista is no longer supported and
   receives no security updates. Consider Windows 10/11 or a lightweight Linux
   distribution.
4. **Run a full ClamAV scan** with updated definitions — the definitions on this
   machine date from 2016. Updated definitions may find threats that were missed.
5. **Clean the vents and fan** — the machine is running warm and the CPU is
   throttling. A dust clean-out and fresh thermal paste will help.

---

_This report was generated automatically by the Nielsoln Rescue Toolkit_  
_Report date: 27 April 2026_
