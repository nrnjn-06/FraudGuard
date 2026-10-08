# FraudGuard: Scoring Methodology & Technical Documentation

This document specifies the exact architecture, mathematical formulas, score thresholds, contribution accounting, and missing-data policies for the **FraudGuard Scoring Engine**.

---

## 1. Core Principle: Conceptual Separation

```text
                  WEBSITE
                     │
                     ▼
              Chrome Extension
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Rule-Based Detection     Domain Analysis
          │                     │
          ▼                     ▼
     Detected UI           WHOIS / SSL /
                           Domain Signals
          │                     │
          ▼                     ▼
       ML Model            Store Trust
          │                     │
          ▼                     ▼
   ML Probability       Store Trust Score (0–100)
          │
          ▼
   UI Safety Score (0–100)
          │
          └──────────┬──────────┘
                     ▼
              FraudGuard State
                     ▼
          FraudGuard Assessment UI
```

> [!IMPORTANT]
> **DECEPTIVE UI ≠ FRAUD**  
> A well-known, legitimate global e-commerce enterprise may employ aggressive countdown timers, scarcity badges, or promotional popups. Concurrently, a newly created phishing or counterfeit store may present a clean, calm, unaggressive user interface.
> 
> Therefore, FraudGuard strictly separates:
> 1. **UI Safety Score**: Measures user interface safety and the absence of manipulative, deceptive, or coercive design patterns on the webpage.
> 2. **Store Trust Score**: Measures technical domain longevity, cryptographic certificate health, and DNS infrastructure credibility.
> 
> Neither score incorporates or influences the other. Both scores operate in the same direction: **Higher score = safer**.

---

## 2. UI Safety Score (0–100)

### 2.1 Definition & Directionality
The **UI Safety Score** quantifies the safety of the user interface based on the absence of manipulative or coercive interface practices detected across the rendered document object model (DOM) and validated by machine learning.
- **Directionality**: Higher = safer.
- **`100`**: Clean interface; no meaningful deceptive UI evidence detected.
- **`0`**: Severe, multifaceted deceptive UI evidence detected.

### 2.2 Contributing Signals
1. **Rule-Based Detections**:
   - Volume and count of flagged DOM leaf nodes.
   - Severity classification:
     - **Low** (Urgency, Scarcity, Social Proof): Nudges and artificial peer/inventory pressure.
     - **Medium** (Countdown Timers): Fabricated expiration deadlines and time constraints.
     - **High** (Pre-selected Recurring Payments / Subscriptions): Direct financial deception (inertia selling).
2. **Category Diversity Bonus**:
   - Presence of multiple distinct dark pattern categories indicating deliberate, multifaceted behavioral manipulation.
3. **Machine Learning Confirmation**:
   - Output probability from the TF-IDF + Logistic Regression text classifier ($P_{dark} \in [0.0, 1.0]$) trained on the dark pattern corpus.

### 2.3 Mathematical Formula & Evidence Blending

#### Step 1: Rule Risk Evidence ($E_{rules} \in [0, 100]$)
Each detected element contributes severity points:
- Low Severity Detection: $+15\text{ pts}$
- Medium Severity Detection: $+25\text{ pts}$
- High Severity Detection: $+40\text{ pts}$

A category diversity factor is added if multiple categories appear:
- $\ge 2$ unique categories: $+10\text{ pts}$
- $\ge 3$ unique categories: $+15\text{ pts}$

$$\text{Raw Rule Score} = \sum_{i=1}^{N} \text{SeverityWeight}_i + \text{DiversityBonus}$$
$$E_{rules} = \min(100, \text{Raw Rule Score})$$

#### Step 2: Machine Learning Risk Evidence ($E_{ml} \in [0, 100]$)
When ML inference results are available, peak deceptive signal and mean probability across flagged texts are blended:
$$E_{ml} = \min\left(100, \left(0.60 \times \max(P_{dark}) + 0.40 \times \text{avg}(P_{dark})\right) \times 100\right)$$

#### Step 3: Risk Evidence Blending ($R \in [0, 100]$)
- **When ML Inference is Available**:
  $$R = \text{round}(0.60 \times E_{rules} + 0.40 \times E_{ml})$$
- **When ML is Unavailable (Offline / Fallback)**:
  $$R = \text{round}(E_{rules})$$
- **When Zero Detections Exist**:
  $$R = 0$$

#### Step 4: Reversal to UI Safety Score
$$\text{UI Safety Score} = \max(0, \min(100, 100 - R))$$

### 2.4 UI Safety Contribution Accounting
UI Safety contributions provide human-readable, non-confusing signal accounting. The sum of contributions strictly equals the `ui_safety_score`:

$$\sum \text{ui\_safety\_contributions} \equiv \text{ui\_safety\_score}$$

- **Interface Design Safety** (up to 60 pts when ML is available, up to 100 pts without ML):
  $$\text{Contribution} = \max(0, \text{round}(0.60 \times (100 - E_{rules})))$$
- **Language Analysis Safety** (up to 40 pts):
  $$\text{Contribution} = \max(0, \text{round}(0.40 \times (100 - E_{ml})))$$

Missing data or benign patterns are never represented as negative values.

---

## 3. Store Trust Score (0–100)

### 3.1 Definition & Four-Factor Architecture
The **Store Trust Score** evaluates empirical, cryptographic, and infrastructural evidence gathered from the domain.

```text
PREVIOUS BASELINE METHODOLOGY (REPLACED):
    Trust = 50 (Baseline) + Δage + Δssl + Δstructure + Δwhois

CURRENT EVIDENCE-BASED METHODOLOGY (EXACTLY 4 FACTORS):
    Store Trust Score = Domain Age (max 40) + SSL/TLS (max 20) + Domain Structure (max 20) + WHOIS / Registration (max 20)
    Total Maximum = 100 points (Zero Baseline, Direct Addition, No Normalization)
```

#### Why the Baseline Was Removed:
1. **Flawed Prior Assumption**: A fixed baseline of 50 artificially assumed moderate credibility prior to observing empirical evidence.
2. **Threshold Distortion**: With LOW = 0–30, MEDIUM = 31–75, and HIGH = 76–100, an unverified domain with valid SSL automatically started at MEDIUM or jumped into HIGH.
3. **Existence is Not Trustworthiness**: A domain must not receive trust points simply because it exists or because a registrar is present.
4. **Encryption ≠ Merchant Credibility**: Valid TLS proves transport encryption, not that the merchant or storefront is legitimate.
5. **Exact Mathematical Accounting**: Removing the baseline ensures that the sum of contribution points directly equals the final score: $\sum \text{store\_trust\_contributions} \equiv \text{store\_trust\_score}$.

### 3.2 Core Architectural Principles
1. **Domain Age is a Confidence Signal**: Historical longevity provides evidence of standing and operational history; it is a confidence factor, NOT a fraud verdict.
2. **A New Domain is Not Automatically Fraudulent**: Young domains are normal for emerging enterprises. A young domain reduces confidence due to limited historical data, but does NOT by itself prove malice.
3. **Valid TLS Does Not Establish Merchant Legitimacy**: HTTPS is ubiquitous, free, and automated. While invalid SSL is a critical security vulnerability, valid SSL merely verifies standard transport security (+20 pts max).
4. **Registrar Identity Alone is Not a Trust Signal**: Registrar names alone do not establish store credibility. Points are awarded for consistent registration records, lifecycle stability, and redundant DNS infrastructure.
5. **Missing Data is Not Negative Evidence**: Missing telemetry (e.g. privacy-redacted WHOIS) is represented as `INSUFFICIENT_DATA` (0 pts awarded) and is NOT penalized as negative or fraudulent evidence.
6. **Direct Infrastructure Telemetry Only**: The system relies strictly on direct domain and cryptographic infrastructure telemetry.

### 3.3 Four-Factor Evidence Model (Max 100 Points)

$$\text{Store Trust Score} = P_{\text{age}} + P_{\text{ssl}} + P_{\text{structure}} + P_{\text{whois}}$$

#### Component 1: Domain Age & Longevity ($P_{\text{age}}$, Max 40 pts)
Evaluated directly from WHOIS or domain telemetry `domain_age_days`:
- $> 5\text{ years}$ ($> 1825\text{ days}$): **40 pts** (Highly established, longstanding web presence)
- $2\text{ to }5\text{ years}$ ($730\text{ to }1825\text{ days}$): **35 pts** (Mature, established domain)
- $1\text{ to }2\text{ years}$ ($365\text{ to }729\text{ days}$): **30 pts** (Seasoned domain)
- $181\text{ to }364\text{ days}$: **22 pts** (Developing domain presence)
- $91\text{ to }180\text{ days}$: **15 pts** (Developing domain presence)
- $30\text{ to }90\text{ days}$: **8 pts** (Young domain; limited historical confidence)
- $< 30\text{ days}$: **0 pts** (Newly created domain; elevated risk for ephemeral stores)
- *Age Unverified / Unavailable*: **0 pts** (Status: `unverified` / `insufficient_data`; missing data is not penalized as fraud)

#### Component 2: SSL / TLS Health & Encryption Hygiene ($P_{\text{ssl}}$, Max 20 pts)
Evaluated from the SSL certificate analyzer:
- **Valid Certificate + Hostname Verified**: **+20 pts** (Valid transport encryption confirmed)
- **Valid Certificate but Incomplete Verification**: **+10 pts** (Valid certificate, but hostname verification could not be confirmed)
- **Unable to Verify / Missing Data**: **0 pts** (Status: `unverified`; neutral)
- **Invalid / Expired / Hostname Mismatch / Failed**: **0 pts** (Status: `invalid_or_untrusted`; triggers critical signal escalation)

#### Component 3: Domain Structure ($P_{\text{structure}}$, Max 20 pts)
Evaluated from the structural analyzer (`domain_characteristics`):
- **Clean Standard Hostname (No Flags)**: **20 pts** (Standard alphanumeric conventions)
- **Single Mild Anomaly**: **12 pts** (e.g. single long hostname, excessive hyphens, or numeric density)
- **Multiple Suspicious Anomalies ($\ge 2$ flags)**: **5 pts** (Multiple anomalous structural characteristics)
- **Strong Homograph / Punycode Signal (`xn--`)**: **0 pts** (Triggers critical signal escalation)

#### Component 4: WHOIS & Registration Quality ($P_{\text{whois}}$, Max 20 pts)
Evaluated from WHOIS registration records and DNS nameservers:
- **Normal / Consistent Registration Evidence**: **20 pts** (Accredited registrar + $\ge 2$ redundant name servers + consistent dates)
- **Partial but Usable Registration Data**: **10 pts** (Identified registrar or nameservers with minimal redundancy)
- **Suspicious / Restricted Registry Status**: **5 pts** (e.g. `clientHold`, `redemptionPeriod`, `pendingDelete`)
- **WHOIS Unavailable / Privacy Redacted**: **0 pts** (Status: `insufficient_data`; missing data is not penalized as fraud)

---

## 4. Score Interpretation & Evidence Bands

Both scores map to standardized evidence tiers with identical classification boundaries:

| Score Range | Store Trust Level | UI Safety Level | Operational Interpretation |
| :---: | :---: | :---: | :--- |
| **0 – 30** | **LOW TRUST** | **LOW UI SAFETY** | Low Trust: Unestablished or young domain \| Low UI Safety: Coercive/manipulative interface |
| **31 – 75** | **MEDIUM TRUST** | **MEDIUM UI SAFETY** | Medium Trust: Standard infrastructure \| Medium UI Safety: Moderate promotional pressure |
| **76 – 100** | **HIGH TRUST** | **HIGH UI SAFETY** | High Trust: Seasoned enterprise standing \| High UI Safety: Clean, transparent interface |
| `null` | **INSUFFICIENT DATA** | *N/A* | Technical telemetry unavailable or inconclusive |

---

## 5. Handling Missing Data & Edge Cases

1. **Missing WHOIS Data**: Does not penalize the store (0 delta). Modern privacy regulations (GDPR) frequently redact WHOIS records for legitimate sites.
2. **Missing Domain Age**: Leaves the age factor at 0 delta without assuming guilt or legitimacy.
3. **Unresolvable Domain Intelligence**: If WHOIS, SSL, and DNS telemetry are completely unavailable (e.g., connection timeout, intranet, local IP), `store_trust_score` is returned as `None` with `store_trust_level: "INSUFFICIENT_DATA"`.
4. **Offline ML Inference**: If the backend ML service is unreachable, the UI Safety Score computes directly from rule-based DOM signals without failure.
5. **Exact Contribution Invariance**: For both Store Trust and UI Safety, contribution points strictly sum to their respective scores under all network conditions.
