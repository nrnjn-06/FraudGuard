# FraudGuard: Overall Risk Assessment Methodology

> **Official Disclaimer:**  
> **"FraudGuard provides an evidence-based risk assessment and does not guarantee that a website is fraudulent or legitimate."**

---

## 1. System Overview & Core Architectural Principle

FraudGuard synthesizes multi-layered empirical signals—DOM heuristics, machine-learning text classification, and domain/cryptographic infrastructure intelligence—into a transparent, reproducible, page-level risk classification.

```text
                                  RENDERED WEBPAGE
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
          DOM HEURISTICS                                    DOMAIN & SSL
         (Urgency, Scarcity, Social Proof,             (Domain Age, SSL Validity,
          Countdowns, Recurring Charges)                Punycode, DNS Structural Flags)
                  │                                               │
                  ▼                                               ▼
            ML CLASSIFIER                                  SCORING ENGINE
         (TF-IDF + Logistic Regression)                ┌───────────┴───────────┐
                  │                                    ▼                       ▼
                  ▼                               Store Trust              UI Safety
            ML Dark Pattern                       Score (0–100)           Score (0–100)
            Probabilities                              │                       │
                  │                                    │                       │
                  └───────────────────────┬────────────┘                       │
                                          │                                    │
                                          ▼                                    ▼
                             OVERALL RISK ASSESSMENT ENGINE
                             ┌─────────────────────────┐
                             │  Evidence Synthesis     │
                             │  Store Trust Priority   │
                             │  9-Cell Decision Matrix │
                             │  Critical Signal Logic  │
                             │  Explainability Engine  │
                             └────────────┬────────────┘
                                          │
                                          ▼
                             OVERALL RISK ASSESSMENT
                             - Classification: LOW | MEDIUM | HIGH
                             - Prescribed User Guidance
                             - Transparent Risk Reasons (Bullets)
```

### The Non-Equivalence Axiom: DECEPTIVE UI ≠ FRAUD
A central requirement of FraudGuard is the conceptual independence of consumer persuasion tactics and fraudulent store infrastructure:
* **UI Safety Score and Overall Risk are intentionally separated:** A website can exhibit aggressive promotional UI while maintaining low overall website risk when strong domain trust evidence exists and no critical security indicators are present.
* **FraudGuard does not treat the presence of dark patterns as definitive evidence of fraud:** Lower UI Safety Score measures the amount/strength of potentially deceptive or manipulative interface patterns detected on the page. Overall Risk estimates how risky it is for the user to trust/proceed with the website based on domain trust, security evidence, UI safety evidence, and critical signals.
* **Established Aggressive Merchants (e.g., major e-commerce platforms):** A prominent global e-commerce retailer may aggressively deploy countdown timers, artificial scarcity banners, and promotional social proof. Because domain trust is strong (e.g. 100/100) and no critical security/domain flags exist, the overall website risk is **LOW** or **MEDIUM**, while the UI Safety Score remains prominently visible (e.g. 26/100).
* **Unseasoned Benign Sites:** A newly established boutique store may possess little domain age or public WHOIS history, yet deploy an entirely tranquil, honest interface without any manipulative dark patterns (**MEDIUM RISK**, not fraud).

Therefore:
$$\text{Deceptive UI} \neq \text{Fraud}$$
FraudGuard **never** averages $\frac{\text{Store Trust} + \text{UI Safety}}{2}$ or treats the scores as interchangeable scalar opposites. Instead, risk is evaluated through a deterministic decision matrix where **Store Trust determines the base risk**, and **UI Safety modifies the risk within that trust level**.

---

## 2. Inputs to the Risk Assessment Engine

The Risk Assessment Engine (`FraudGuard/backend/scoring/risk_engine.py`) takes five structured input telemetry vectors:

1. **Store Trust Score ($S_{trust} \in [0, 100]$) and Level:**
   Calculated based on domain age, SSL/TLS certificate integrity, hostname verification, and structural DNS flags.
2. **UI Safety Score ($S_{ui} \in [0, 100]$) and Level:**
   Calculated based on rule-based DOM element frequency, severity weightings, pattern diversity bonus, and ML probability blend ($100 - R$).
3. **Machine Learning Text Evidence:**
   Inference probabilities ($P_{dark} \in [0.0, 1.0]$) and categorical classifications (`DARK_PATTERN` vs `NOT_DARK_PATTERN`) generated by the TF-IDF and Logistic Regression pipeline trained on the e-commerce dark pattern corpus.
4. **Domain & Cryptographic Evidence:**
   Exact domain age in days, WHOIS registration availability, SSL cipher validity, hostname certificate match, and suspicious structural flags (e.g., punycode/homograph, excessive hyphens).
5. **Critical Interface Signals & Detections:**
   High-risk architectural dark patterns such as pre-selected recurring billing/memberships, domain age $< 30\text{ days}$, or active SSL certificate revocation/mismatch.

---

## 3. Store Trust Score Interpretation

The Store Trust Score reflects technical longevity and transport-layer infrastructure credibility:

* **Score Ranges & Evidence Bands:**
  * **HIGH TRUST ($76 - 100$):** Seasoned domain registration ($\ge 2\text{ years}$ or $\ge 5\text{ years}$), fully validated SSL certificate with verified hostname match, and zero deceptive structural flags.
  * **MEDIUM TRUST ($31 - 75$):** Standard domain infrastructure, moderate operating history, or valid TLS encryption without extensive multi-year longevity.
  * **LOW TRUST ($0 - 30$):** Extremely young domain ($< 30\text{ days}$), missing registration data, unverified host identity, or structural anomalies.
  * **INSUFFICIENT DATA:** WHOIS/DNS queries unresolvable or blocked; backend evaluates based strictly on available page evidence without penalizing the merchant.

* **Directionality:** Higher is safer ($100 = \text{Maximum Trust}$, $0 = \text{Zero Verifiable Trust}$).

---

## 4. UI Safety Score Interpretation

The UI Safety Score quantifies user interface safety and freedom from deceptive patterns:

* **Score Ranges & Evidence Bands:**
  * **LOW UI SAFETY ($0 - 30$):** Strong, pervasive, or multifaceted manipulative patterns detected across the page. Lower UI Safety indicates stronger deceptive UI concerns.
  * **MEDIUM UI SAFETY ($31 - 75$):** Moderate density of artificial urgency, scarcity, or countdown timers.
  * **HIGH UI SAFETY ($76 - 100$):** Minimal or zero deceptive patterns detected. Standard, tranquil browsing experience.

* **Directionality:** Higher is safer ($100 = \text{Clean UI}$, $0 = \text{Severe Deceptive Patterns}$).

---

## 5. Machine Learning Evidence Interpretation

Machine learning text classification output serves as evidentiary corroboration rather than an autonomous decision oracle:

1. **Evidence Amplification:**
   * When both DOM heuristics flag a pattern and ML indicates $P_{dark} \ge 0.80$ with classification `DARK_PATTERN`, the deceptive UI finding is confirmed as high-intensity.
2. **Safeguard Against Unilateral Classification:**
   * A high ML probability on isolated sentence fragments does **not** trigger a `HIGH RISK` page rating on its own. ML outputs are weighted alongside domain trust and DOM hierarchy.
3. **No Synthetic Extrapolation:**
   * The risk engine operates strictly on real ML inference probabilities delivered from `/analyze-text`. If ML analysis is pending or disabled, the engine relies on heuristic leaf counts.

---

## 6. Domain & Security Evidence Interpretation

Infrastructure evidence is interpreted with strict security boundaries:

1. **SSL Validity as a Baseline, Not an Endorsement:**
   * A valid SSL/TLS certificate confirms that communication is encrypted in transit between the client and host. Over $80\%$ of modern phishing websites utilize free automated SSL certificates. Therefore, valid SSL prevents automatic penalties but does **not** certify merchant legitimacy.
2. **Missing Information Policy:**
   * Privacy-protected WHOIS or unlisted registration dates do **not** imply fraud. Millions of legitimate independent businesses conceal registrar details for privacy compliance (GDPR). Missing WHOIS is treated as `INSUFFICIENT DATA`, never as proof of malice.

---

## 7. Critical Signals & High-Impact Escalation Rules

FraudGuard isolates high-impact signals that possess direct financial or technical harm potential. Critical signals override the normal matrix and escalate Overall Risk to `HIGH RISK`:

| Critical Signal Identifier | Trigger Condition | Technical & Behavioral Rationale | Escalation Effect |
| :--- | :--- | :--- | :--- |
| `CRITICAL_RECURRING_PAYMENT` | Pre-checked recurring billing, hidden subscription, or negative option billing. | Inertia selling trap: commits the consumer to continuous financial withdrawals without an affirmative opt-in click. | Escalates Overall Risk to `HIGH RISK`. |
| `CRITICAL_NEW_DOMAIN` | Domain registration age $< 30\text{ days}$. | Strongest statistical indicator of disposable phishing, counterfeit drop-shipping, or fly-by-night fraud shops. | Escalates Overall Risk to `HIGH RISK`. |
| `CRITICAL_INVALID_SSL` | Expired, self-signed, untrusted root, or hostname mismatch certificate. | Broken transport encryption: enables active adversary-in-the-middle (AITM) credential and payment eavesdropping. | Immediate escalation to `HIGH RISK` across all trust bands. |
| `CRITICAL_PUNYCODE_HOMOGRAPH` | Hostname uses Punycode (`xn--`) or Cyrillic/Greek homoglyphs spoofing Latin characters. | Deceptive character substitution engineered to deceive human visual inspection (brand spoofing). | Escalates Overall Risk to `HIGH RISK`. |
| `CRITICAL_MULTIPLE_STRUCTURAL_FLAGS` | Hostname exhibits $\ge 2$ anomalous structural flags (excessive hyphens, numeric density, deep subdomains). | Non-standard hostname structure frequently associated with automated domain generation. | Escalates Overall Risk to `HIGH RISK`. |

---

## 8. Decision Matrix & Combination Rules (Store Trust Priority Model)

Store Trust determines the base level of Overall Risk. UI Safety modifies the risk within that trust level:

### LOW TRUST (0–30): Base Risk is HIGH RISK
- **LOW UI SAFETY (0–30)** $\rightarrow$ **HIGH RISK** (Low trust domain compounded by deceptive interface patterns)
- **MEDIUM UI SAFETY (31–75)** $\rightarrow$ **HIGH RISK** (Low trust domain combined with moderate promotional pressure)
- **HIGH UI SAFETY (76–100)** $\rightarrow$ **MEDIUM RISK** (Clean, unaggressive interface mitigates unseasoned domain to Medium Risk)

### MEDIUM TRUST (31–75): Base Risk is MEDIUM RISK
- **LOW UI SAFETY (0–30)** $\rightarrow$ **HIGH RISK** (Heavy deceptive UI elevates moderate trust domain to High Risk)
- **MEDIUM UI SAFETY (31–75)** $\rightarrow$ **MEDIUM RISK** (Standard infrastructure with moderate promotional pressure)
- **HIGH UI SAFETY (76–100)** $\rightarrow$ **MEDIUM RISK** (Standard infrastructure with clean UI maintains moderate base risk)

### HIGH TRUST (76–100): Base Risk is LOW RISK
- **LOW UI SAFETY (0–30)** $\rightarrow$ **MEDIUM RISK** (Heavy deceptive UI modifies High Trust domain to Medium Risk)
- **MEDIUM UI SAFETY (31–75)** $\rightarrow$ **LOW RISK** (Established infrastructure absorbs moderate promotional pressure)
- **HIGH UI SAFETY (76–100)** $\rightarrow$ **LOW RISK** (Established infrastructure and calm UI maintain Low Risk)

### 9-Cell Decision Matrix Summary Table

| Store Trust Band | UI Safety Band | Overall Risk | Decision Matrix Case | Operational Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **LOW (0–30)** | **LOW (0–30)** | **HIGH RISK** | `LOW_TRUST_LOW_UI_SAFETY` | Unseasoned domain compounded by heavy deceptive interface patterns. |
| **LOW (0–30)** | **MEDIUM (31–75)** | **HIGH RISK** | `LOW_TRUST_MED_UI_SAFETY` | Low trust domain with promotional pressure; elevated user risk. |
| **LOW (0–30)** | **HIGH (76–100)** | **MEDIUM RISK** | `LOW_TRUST_HIGH_UI_SAFETY` | Unseasoned domain, but completely clean and non-deceptive interface. |
| **MEDIUM (31–75)** | **LOW (0–30)** | **HIGH RISK** | `MED_TRUST_LOW_UI_SAFETY` | Moderate domain standing overridden by coercive UI patterns. |
| **MEDIUM (31–75)** | **MEDIUM (31–75)** | **MEDIUM RISK** | `MED_TRUST_MED_UI_SAFETY` | Standard domain infrastructure with moderate promotional pressure. |
| **MEDIUM (31–75)** | **HIGH (76–100)** | **MEDIUM RISK** | `MED_TRUST_HIGH_UI_SAFETY` | Standard domain infrastructure with clean interface. |
| **HIGH (76–100)** | **LOW (0–30)** | **MEDIUM RISK** | `HIGH_TRUST_LOW_UI_SAFETY` | Established domain with heavy promotional pressure (e.g. major retail). |
| **HIGH (76–100)** | **MEDIUM (31–75)** | **LOW RISK** | `HIGH_TRUST_MED_UI_SAFETY` | Established domain with moderate promotional cues. |
| **HIGH (76–100)** | **HIGH (76–100)** | **LOW RISK** | `HIGH_TRUST_HIGH_UI_SAFETY` | Established domain with clean, transparent browsing experience. |

---

## 9. Risk Levels & Threshold Summary

| Risk Level | Visual Display | Hex Token | Operational Interpretation |
| :--- | :--- | :--- | :--- |
| **LOW RISK** | Green Shield & Badges | `#10b981` | Webpage demonstrates robust infrastructure credibility and absence of critical security indicators. Overall website risk is low. |
| **MEDIUM RISK** | Amber / Yellow | `#f59e0b` | Webpage presents mixed signals: e.g. unseasoned merchant with clean UI, or trusted merchant with promotional pressure. |
| **HIGH RISK** | Red Shield & Badges | `#ef4444` | Strong convergent evidence of deceptive interfaces combined with unverified infrastructure, or triggered critical security signals. |
| **INSUFFICIENT DATA** | Gray / Slate | `#64748b` | Network disconnected or backend unavailable. Extension fails gracefully without issuing alarmist fraud warnings. |

---

## 10. Explainability & Dynamic Reason Generation

The Risk Assessment Engine automatically produces transparent, user-facing rationale bullet points (`risk_reasons`) for every evaluation:

### Example: Established Merchant with Low UI Safety (e.g. Major Retail Platform)
```json
{
  "store_trust_score": 100,
  "store_trust_level": "HIGH",
  "ui_safety_score": 26,
  "ui_safety_level": "LOW",
  "overall_risk": "MEDIUM",
  "decision_matrix_case": "HIGH_TRUST_LOW_UI_SAFETY",
  "risk_guidance": "3 significant risk indicators detected. The domain has high trust, but deceptive UI patterns were detected; review findings before proceeding.",
  "risk_summary": "High levels of potentially deceptive UI were detected. While strong domain trust establishes low base risk, prominent deceptive interface patterns elevate the evaluation to Medium Risk.",
  "risk_reasons": [
    "✓ Primary factor — High Store Trust: established registration and valid SSL/TLS certificate establish a low base risk.",
    "⚠ Secondary factor — Low UI Safety: multiple high-intensity patterns detected (Scarcity, Social Proof, Urgency).",
    "⚖ Store Trust priority: High Store Trust establishes low base risk, but lower UI Safety modifies Overall Risk to MEDIUM RISK."
  ]
}
```

### Example: Unverified Infrastructure + Low UI Safety
```json
{
  "store_trust_score": 0,
  "store_trust_level": "LOW",
  "ui_safety_score": 15,
  "ui_safety_level": "LOW",
  "overall_risk": "HIGH",
  "decision_matrix_case": "LOW_TRUST_LOW_UI_SAFETY_ESCALATED_CRITICAL",
  "risk_guidance": "Multiple strong risk indicators detected. Exercise caution before providing sensitive information or making a payment.",
  "risk_reasons": [
    "⚠ Primary factor — Low Store Trust: newly created, unseasoned, or unverified infrastructure elevates base risk to High Risk.",
    "⚠ Secondary factor — Low UI Safety: multiple high-intensity patterns detected (Recurring Payment, Urgency).",
    "⚠ ML text classifier confirmed dark-pattern language with high probability (94%).",
    "🚨 Critical indicator override: Pre-selected recurring payment or subscription option detected."
  ]
}
```

---

## 11. Missing-Data & Offline Fallback Policy

1. **Offline Backend:**
   * If the FastAPI service on port 8001 is unreachable, the extension displays `OFFLINE` status in the collapsed widget and drawer. The website is **never** flagged as `HIGH RISK` simply because the local analysis daemon is unavailable.
2. **Missing WHOIS / RDAP Data:**
   * When registrars redact domain creation timestamps, Store Trust marks WHOIS as unverified and relies on SSL certificate attributes and leaf heuristics.
3. **Pending ML Classifications:**
   * While asynchronous ML classification requests are in flight, the scoring and risk engines utilize rule counts and leaf node severities to ensure immediate UI responsiveness.

---

## 12. Methodological Limitations

1. **Heuristic Scope:** Heuristic regular expressions inspect DOM text nodes and countdown timer mutations; novel obfuscated CSS or canvas-rendered countdown timers may evade extraction.
2. **ML Context Window:** The model classifies discrete text snippets (up to 512 characters) rather than the global page layout narrative.
3. **Domain Registrar Privacy:** Widespread privacy protection services prevent exact registrant entity identification, limiting domain scoring to registration age and DNS structural flags.
4. **Advisory System:** FraudGuard is an academic client-side decision support system designed to inform user scrutiny, not an authoritarian payment blocking firewall.
