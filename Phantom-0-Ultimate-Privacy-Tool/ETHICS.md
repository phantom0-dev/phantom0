# Embedded Ethics Protocol (“311”)

Phantom-0 v1.0.0 is provided as a privacy, security, and digital hygiene framework for lawful, ethical use only.
By downloading, using, or modifying this software/tool, **YOU AGREE** to the following terms:

**1. Authorized Use Only**
    This software/tool is intended solely for lawful, ethical purposes, including but not limited to:
    • Personal use by individuals seeking enhanced privacy, digital hygiene, and security.
    • Educational and research use for learning about cybersecurity, privacy, and system hardening.
    • Organizational and industry use by businesses, nonprofits, and other entities to strengthen their security posture.
    • Professional use by IT/security practitioners for compliance, defensive hardening, and privacy protection.
    
**2. Prohibited Use**
    This software/tool must NOT be used for:
    • Harming others.
    • Malicious or unlawful intent.
    • Concealing, impeding, or destroying evidence.
    • Obstructing justice, investigations, or lawful seizure of property.
    • Any activity in violation of local, state, federal, or international law.
    
**3. No Warranty**
    This software/tool is provided “AS IS,” without warranty of any kind, express or implied. No guarantee is made regarding:
    • Functionality, reliability, fitness for a particular purpose, or security outcomes.
    • Compatibility with any system, distribution, or environment.
    
**4. Limitation of Liability**
    In no event shall the authors, contributors, or distributors of this software be liable for:
    • Direct, indirect, incidental, special, exemplary, or consequential damages.
    • Any claim, damages, or other liability, whether in contract, tort, or otherwise, arising from, out of, or in connection with this software or its use.
    
**5. User Responsibility**
    By using this software/tool, you accept full responsibility and liability for:
    • Compliance with all applicable laws, policies, and regulations.
    • Ensuring your use is lawful, ethical, and does not violate third-party rights.
    • All risks associated with installation, configuration, execution, or modification.
    
**6. Ethical Compliance**
    This project includes an Ethics Compliance Gate that requires acknowledgment before use. If you cannot comply with these conditions, do not use this software.

**Operational Safeguards**
1. **Affirmative Consent Gate** — `AGREE_TO_ETHICS=1` must be set in `config/phantom0.conf`.
2. **DRY_RUN First** — All modules default to DRY_RUN; destructive actions require explicit opt‑in.
3. **Context Checks** — Modules must verify scope, ownership, and target safety before acting.
4. **Auditability** — Produce an audit log (RAM‑resident by default) summarizing what ran in DRY_RUN.
5. **No Weaponization** — Public repository ships **no anti‑forensics code**. Private modules must comply with this policy.

**User Pledge (required)**  
By setting `AGREE_TO_ETHICS=1`, you confirm:  
- You will use Phantom‑0 for lawful privacy, compliance, research, or defensive security.  
- You will not employ Phantom‑0 to harm others, use for malicious intents, conceal crimes, or obstruct justice/investigations.

**Report Misuse/Security Issues**: see `SECURITY.md`.
