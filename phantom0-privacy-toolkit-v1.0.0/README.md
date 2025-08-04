# 🛡️ Phantom-0 Privacy Toolkit
--------------------------------------------------------------------------------

## Table of Contents
- [Mission Statement](#mission)
- [IMPORTANT](#IMPORTANT)
- [What is Phantom-0?](#what-is-phantom-0)  
- [Who Is This For?/Who It's Not For](#who-should-use-this)  
- [Features](#features)  
- [So Where Does Phantom-0 Stand?](#rating)  
- [Structure](#structure)  
- [Getting Started](#getting-started)  
- [Usage](#usage)  
- [Verify Your Privacy](#verify-your-privacy)  
- [Legal Disclaimer](#legal-disclaimer)    
- [License](#license)  

--------------------------------------------------------------------------------

## Phantom-0 Mission Statement:
> “A secure, private computing environment built to minimize your digital footprint, reduce metadata exposure, and ensure your personal data remains confidential — empowering you to retain control of your digital identity in a world of pervasive monitoring.”

--------------------------------------------------------------------------------

## ***IMPORTANT***:
*****PHANTOM-0 IS ONLY FOR DEBIAN-BASED SYSTEMS, UNLESS OTHERWISE CUSTOMIZED.*****
Before running Phantom-0, carefully review each script and update any system-specific variables — such as directory paths, network interfaces, usernames, or device identifiers — to match your environment. Remove or adjust sections that don't apply to you (for example, if you do not use Mullvad, Firefox, or Tor).

Phantom-0 is designed as a one-time, fully customizable setup script tailored to individual user needs. While no future versions are planned, the source code is fully open and may be forked, stripped, or expanded based on your personal privacy model.

If you're unsure how to adjust any section, tools like ChatGPT can help tailor it to your system.

--------------------------------------------------------------------------------

## 🔒 What is Phantom-0?  
Phantom-0 is a lightweight privacy and system hygiene toolkit designed for Linux users seeking improved metadata minimization and post-session cleanup:
- ✅ Peace of mind during shutdowns and startups  
- ✅ Increased control over logs, identifiers, and temporary data  
- ✅ Reduces retained digital traces without sacrificing functionality  

--------------------------------------------------------------------------------

## Who Is This For?:
Phantom-0 is intended for advanced Linux users who value session cleanup, system control, and trace minimization:
1. **Privacy-Focused Individuals** — Minimizing digital fingerprints and persistent identifiers
2. **Security Researchers & Developers** — Testing cleanup automation and session hardening
3. **Journalists & Activists** — Requiring discretion and a low-noise system environment
4. **Power Users** — Who prefer terminal-based workflows and scriptable privacy control

## Who It's Not For:
- Users unfamiliar with Linux or CLI-based workflows
- Those seeking GUI-based or "one-click" anonymization tools
- Environments requiring audit trails or persistent log storage
- General-purpose systems where long-term user data must be preserved

--------------------------------------------------------------------------------

## 🛠 Features  
- 🔄 Startup & shutdown routines with customizable cleanup and rotation
- 🧹 Clears logs, shell history, DNS cache, and other transient session data  
- 🧠 Clears volatile memory buffers  
- 🌐 MAC and hostname rotation, DNS cache reset, firewall prep  
- 🔐 Firefox session management with persistence options  
- 🧱 Optional monitoring hooks (e.g., integrity checks)  
- 🧪 System verification with `phantom0.sh verify`  

--------------------------------------------------------------------------------

## So Where Does Phantom-0 Stand?
| Feature                        | Phantom-0 | Tails | Qubes | Whonix | Other Tools |
|-------------------------------|-----------|-------|-------|--------|-----------|
| System log & metadata cleanup | ✅        | ✅    | ❌    | ❌     | ✅           |
| Firefox cleanup + persistence | ✅        | ❌    | ❌    | ✅     | ❌           |
| Basic real-time integrity resp| ✅        | ❌    | ❌    | ❌     | ❌           |
| Intrusion detection hooks     | ✅        | ❌    | ✅    | ❌     | ❌           |
| Persistent full-system install| ✅        | ❌    | ✅    | ✅     | ✅           |
| CLI-friendly deployment       | ✅        | ✅    | ❌    | ❌     | ✅           |

--------------------------------------------------------------------------------

## 📦 Structure  
```
phantom0/
├── phantom0.sh           # Main launcher
├── verify.sh             # Privacy verification script
├── install_phantom0.sh   # Optional installer
├── uninstall_phantom0.sh # Optional uninstaller
├── modules/
│   ├── startup_routine.sh
│   └── shutdown_routine.sh
├── branding/
│   └── phantom0-tagline.png
└── README.md
```

--------------------------------------------------------------------------------

## 🚀 Getting Started  
```bash
git clone https://github.com/phantom0-dev/phantom0.git
cd phantom0
chmod +x install_phantom0.sh
sudo ./install_phantom0.sh
```

--------------------------------------------------------------------------------

## 📖 Usage  

```bash
sudo ./phantom0.sh run startup     # Run startup privacy routine
sudo ./phantom0.sh run shutdown    # Run secure shutdown routine
./phantom0.sh verify               # Verify protections are working
```

--------------------------------------------------------------------------------

## ✅ Verify Your Privacy  
```bash
./phantom0.sh verify
```

--------------------------------------------------------------------------------

## ⚠ Legal Disclaimer  
Phantom-0 is a local privacy enhancement toolkit designed to reduce digital footprint, limit persistent metadata, and support session cleanup.  

This software does **not** interfere with forensic tools, tamper with system timestamps, or attempt to evade legal investigation. It operates transparently using local, auditable Bash scripts.

Use of this toolkit is entirely at your discretion. You are solely responsible for how you configure, deploy, and operate Phantom-0. It is your responsibility to ensure compliance with any laws, policies, or terms of use relevant to your environment.

Phantom-0 is **not a complete security solution.** It is a privacy hygiene utility that should be used in conjunction with proper security practices such as disk encryption, firewalls, secure VPNs, and hardened kernels.

No tool can guarantee absolute privacy or anonymity. Use Phantom-0 responsibly and at your own risk.

--------------------------------------------------------------------------------

## 📜 License  
© 2025 Phantom-0 Project | Licensed under the GNU GPLv3. See [LICENSE](LICENSE) for details.
