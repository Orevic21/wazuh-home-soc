# Home SOC: Threat Detection Lab with Wazuh + Suricata

A self-hosted Security Operations Center lab built to detect real attack techniques against a deliberately vulnerable target, using Wazuh as the SIEM and Suricata as a network-based IDS sensor. Built to demonstrate detection engineering skills — not just tool deployment.

## Overview

Modern SOC work isn't just "install a SIEM and watch the dashboard." It's understanding *why* a detection gap exists, and knowing how to close it. This lab simulates a small, realistic environment: an attacker box, a legacy/vulnerable target with no native logging support, and a SIEM stack that has to work around that constraint using network-layer visibility instead of host agents.

**Key architectural decision:** the target (Metasploitable 2) runs an OS too old to support a modern Wazuh agent or even a syslog forwarder with internet access. Rather than treat this as a blocker, the project pivots to full network-based detection via Suricata — a realistic pattern for legacy, IoT, or OT assets that can't be instrumented directly.

## Architecture

```
┌─────────────┐         attacks          ┌──────────────────────┐
│   Kali VM   │ ────────────────────────▶│   Metasploitable 2   │
│ (attacker + │                           │  (unmonitored victim, │
│  Suricata   │                           │   no agent, no       │
│  sensor +   │                           │   internet access)   │
│  Wazuh agent│                           └──────────────────────┘
└──────┬──────┘
       │ eve.json (Suricata alerts/events)
       │ forwarded via Wazuh agent
       ▼
┌─────────────────────┐
│   Wazuh Manager      │
│   (Amazon Linux 2023)│
│   Indexer + Dashboard│
└─────────────────────┘
```

All three VMs run on VirtualBox, NAT-networked on `192.168.0.0/24`.

| Component | Role | OS |
|---|---|---|
| Wazuh Manager | SIEM: indexer, dashboard, rule engine | Amazon Linux 2023 |
| Kali Linux | Attacker + Suricata network sensor + Wazuh agent | Kali (Debian-based) |
| Metasploitable 2 | Vulnerable target, unmonitored | Ubuntu 8.04 (legacy) |

## Why Suricata runs on the attacker box

Suricata needs visibility into traffic between the attacker and the target. Two options exist: a dedicated sensor VM with a promiscuous/mirrored interface, or running the sensor on one of the two hosts already in the traffic path. Since the Wazuh manager (Amazon Linux 2023) doesn't have EPEL support and made installing Suricata impractical, and the target can't run any agent at all, Suricata runs directly on the Kali box. This means it sees 100% of the attack traffic on its own interface with no promiscuous mode or span port required, and ships its events to the manager through the Wazuh agent already enrolled on Kali.

## Detections

### 1. Reconnaissance — Nmap Scan Detection

**Attack:**
```bash
nmap -sV -A 192.168.0.138
```

**Detection:** Suricata's Emerging Threats ruleset flagged multiple scan-related and protocol-anomaly signatures in real time as the scan touched each open port, including traffic on Metasploitable's exposed UnrealIRCd service (`ET CHAT IRC USER command`).

**Result:** 132+ IDS events generated and correctly classified under the `ids, suricata` rule groups in Wazuh's Threat Hunting view within seconds of the scan completing.

---

### 2. Exploitation — vsftpd 2.3.4 Backdoor (CVE-2011-2523)

**Attack:**
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 > set RHOSTS 192.168.0.138
msf6 > set LHOST 192.168.0.200
msf6 > run
```

Metasploitable's vsftpd 2.3.4 contains a backdoor triggered by a malformed FTP login string, which spawns a root shell on TCP port 6200. The exploit landed cleanly and returned a Meterpreter session as `root`.

**Detection:** Suricata's `GPL ATTACK_RESPONSE id check returned root` signature (SID `2100498`) fired 11 seconds after the shell was spawned, matching the plaintext `uid=0(root)` string in the shell's command output as it crossed the wire on port 6200.

```json
"signature": "GPL ATTACK_RESPONSE id check returned root",
"signature_id": 2100498,
"src_ip": "192.168.0.138",
"src_port": 6200,
"dest_ip": "192.168.0.200",
"direction": "to_client"
```

**Why this matters:** this is network-layer confirmation of a successful root compromise on an asset with zero host-based logging the exact scenario the architecture was designed to handle.

---

### 3. Credential Attack — FTP Brute Force (MITRE ATT&CK T1110)

**Attack:**
```bash
hydra -l msfadmin -P /tmp/quicklist.txt -t 4 ftp://192.168.0.138
```

Hydra attempted multiple FTP logins in rapid succession, correctly identifying the valid credential pair `msfadmin:msfadmin` after several failed attempts.

**Detection status:** Suricata's FTP protocol parser captured every individual `USER`/`PASS` command and server response code in `eve.json` (`event_type: ftp`), confirmed present in the manager's raw event archive:

```json
{"event_type":"ftp","src_ip":"192.168.0.200","dest_ip":"192.168.0.138",
 "dest_port":21,"ftp":{"command":"PASS","command_data":"root",
 "completion_code":["530"],"reply":["Login incorrect."]}}
```

Suricata's default ruleset has no dedicated signature for FTP brute-forcing, since it's a protocol pattern rather than a known-bad string. **A custom Wazuh correlation rule was engineered to close this gap:**

```xml
<group name="suricata,ftp,brute_force,">
  <rule id="100100" level="5">
    <if_sid>86600</if_sid>
    <field name="event_type">^ftp$</field>
    <field name="data.ftp.command">^PASS$</field>
    <description>Suricata: FTP password attempt detected on $(data.dest_ip)</description>
  </rule>

  <rule id="100101" level="10" frequency="4" timeframe="60">
    <if_matched_sid>100100</if_matched_sid>
    <description>Suricata: Possible FTP brute force attack detected - multiple password attempts within 60 seconds</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

**Status:** in progress — the underlying event data is confirmed reaching the manager, and rule syntax is validated via `wazuh-logtest`, but the correlation rule (`100101`) is not yet reliably firing end-to-end. Next debugging step is confirming the decoder field path assigned to nested Suricata FTP fields at parse time via `wazuh-logtest` against a live sample. Tracked as future work below.

## Lessons Learned

- **Legacy targets change your architecture, not just your commands.** Metasploitable 2's outdated toolchain ruled out a modern Wazuh agent and even basic syslog forwarding (no rsyslog, no internet access). Rather than force a host-based approach, the project pivoted to network-based detection — arguably a more realistic pattern for real-world legacy/IoT assets.
- **Package ecosystems aren't interchangeable.** The Wazuh manager's Amazon Linux 2023 base doesn't support classic EPEL, which blocked a direct Suricata install there. Moving the sensor to the Debian-based Kali box, which already sat in the traffic path, sidestepped the problem entirely.
- **Default IDS rulesets are signature-based, not behavioral.** Suricata caught the vsftpd exploit instantly because a known signature existed for it, but had nothing for FTP brute-forcing because that's a *pattern*, not a static string. This is the real justification for writing custom correlation rules in a SIEM rather than relying on out-of-the-box IDS content alone.
- **`archives.log`/`archives.json` are not enabled by default** (`logall`/`logall_json` are `no` out of the box) and are essential for debugging what a SIEM actually received versus what it chose to alert on.

## Future Work

- Finish debugging the FTP brute-force correlation rule (100100/100101) end-to-end
- Add UnrealIRCd backdoor exploitation (CVE-2010-2075) as a fourth detection, since Suricata is already flagging IRC traffic on the target
- Add Samba `usermap_script` RCE (CVE-2007-2447) for a fifth technique
- Wire high-severity alerts into TheHive or Shuffle for automated case creation
- Add active-response to automatically block the attacker IP on repeated brute-force detections

## Tools Used

- [Wazuh](https://wazuh.com/) 4.14.6 — SIEM (manager, indexer, dashboard)
- [Suricata](https://suricata.io/) 8.0.5 — Network IDS
- [Metasploit Framework](https://www.metasploit.com/) / Hydra / Nmap — attack simulation
- VirtualBox — lab virtualization

## MITRE ATT&CK Mapping

| Technique | ID | Status |
|---|---|---|
| Active Scanning | T1595 | ✅ Detected |
| Exploit Public-Facing Application | T1190 | ✅ Detected |
| Brute Force | T1110 | 🔶 In progress |
