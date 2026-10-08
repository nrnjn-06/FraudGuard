# FraudGuard: A Browser-Based Deceptive UI and E-Commerce Fraud Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Chrome Extension](https://img.shields.io/badge/Manifest-V3-4285F4.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E.svg)](https://scikit-learn.org/)
[![Status](https://img.shields.io/badge/Status-Complete-success.svg)]()


## 1. Problem Statement

> *"Security indicators answer 'is the connection encrypted?'—not 'is the interface manipulating me?'"*

Modern e-commerce websites frequently deploy coercive persuasion mechanisms—such as artificial urgency timers, fabricated scarcity counters, herd-pressure social proof, and pre-selected recurring payment options—to pressure consumers into rushed or unintended financial commitments.

Standard browser security measures (such as the padlock icon and TLS verification) only guarantee that data in transit is encrypted. They provide no evaluation of:
1. Whether on-page promotional tactics are coercive, deceptive, or dark patterns.
2. Whether the underlying storefront is an ephemeral, newly registered (< 30 days) phishing entity using automated, free SSL certificates.

**FraudGuard** bridges this critical gap. It is an integrated browser-level defense system combining client-side DOM heuristic detection, machine learning text classification, domain intelligence, and a transparent, explainable Store Trust-priority risk scoring engine.

---

## 2. Key Features

* **Real-Time DOM Inspection**: Scans visible page elements for deceptive patterns using optimized regular expressions and isolates the smallest enclosing DOM leaf nodes without page distortion.
* **Dynamic DOM & SPA Monitoring**: Utilizes a debounced `MutationObserver` (250 ms) to monitor client-side hydration, AJAX calls, and live DOM mutations without CPU thrashing.
* **NLP Dark-Pattern Text Classifier**: Evaluates flagged snippets using a pre-trained TF-IDF + Logistic Regression pipeline trained on balanced e-commerce data (2,356 samples).
* **Cryptographic & Domain Telemetry**: Connects directly to domain infrastructure to extract WHOIS longevity, SSL/TLS handshake validity, Subject Alternative Names (SANs), and DNS structural anomalies.
* **Store Trust-Priority Risk Matrix**: Determines base risk from infrastructure trust and modulates it using UI Safety, adhering to the non-equivalence axiom: **Deceptive UI ≠ Fraud**.
* **Deterministic Critical Signal Overrides**: Escalates Overall Risk to **HIGH** upon encountering severe threats (e.g., domain age < 30 days, invalid SSL, Punycode spoofing, pre-selected recurring billing).
* **Transparent Explainability Engine**: Generates human-readable rationale bullet points (`risk_reasons`), user guidance, and strictly additive score contribution breakdowns.
* **Privacy by Design**: Strictly avoids inspecting passwords, credit card inputs, CVVs, textareas, and general user-input form controls.

---

## 3. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             E-COMMERCE WEBPAGE                              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                         Chrome Extension (Manifest V3)
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
  content.js (DOM Scanner)                                    background.js
  - Filters out sensitive inputs                             - Asynchronous fetch bridge
  - Evaluates 5 deceptive pattern rules                      - Handles CORS / local loopback
  - Deepest DOM leaf node isolation                          - Communicates with FastAPI
  - Injects badges & slide-in drawer                         │
         │                                                   │
         └─────────────────────────────┬─────────────────────┘
                                       ▼ HTTP (Port 8001)
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI BACKEND DAEMON                             │
│                                                                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐  │
│  │  Domain Intelligence  │  │   ML Text Classifier  │  │  Scoring Engine │  │
│  │  - WHOIS longevity    │  │  - TF-IDF Vectorizer  │  │  - Store Trust  │  │
│  │  - SSL/TLS handshake  │  │  - Logistic Regr.     │  │    (40/20/20/20)│  │
│  │  - Structural flags   │  │  - P(dark)probability │  │  - UI Safety    │  │
│  └───────────┬───────────┘  └───────────┬───────────┘  │    (100 - Risk) │  │
│              │                          │              └────────┬────────┘  │
│              └──────────────────────────┼───────────────────────┘           │
│                                         ▼                                   │
│                        ┌─────────────────────────────────┐                  │
│                        │       Overall Risk Engine       │                  │
│                        │   - 9-Cell Decision Matrix      │                  │
│                        │   - 5 Critical Signal Overrides │                  │
│                        │   - Explainability & Guidance   │                  │
│                        └────────────────┬────────────────┘                  │
└─────────────────────────────────────────┼───────────────────────────────────┘
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       USER PRESENTATION & INTERFACE                         │
│  - In-Page Warning Badges (⚠) with rich contextual hover tooltips           │
│  - Floating Status Widget (Low / Medium / High shield indicator)            │
│  - Slide-In Analysis Drawer with 7 detailed analytical telemetry sections   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Deceptive UI Detection Categories

FraudGuard identifies five distinct deceptive interface categories via DOM heuristic inspection:

| Category | Severity | Detection Mechanism | Example Triggers |
| :--- | :---: | :--- | :--- |
| **COUNTDOWN** | Medium | Matches time-pressure expressions (`HH:MM:SS`, `MM:SS`, `ends in X mins`) while ignoring benign timestamps, store hours, or delivery dates. | *"Sale ends in: 00:15:30"*, *"Offer expires in 2 hours"* |
| **SCARCITY** | Low | Detects depleted stock claims and inventory pressure phrasing. | *"Only 2 items left in stock!"*, *"Almost gone"*, *"Selling fast"* |
| **URGENCY** | Low | Detects language encouraging immediate action through artificial deadlines. | *"Hurry! Act now"*, *"Last chance"*, *"Limited time offer"* |
| **SOCIAL PROOF** | Low | Identifies claims of peer activity to induce herd behavior and purchase pressure. | *"43 people are viewing this right now"*, *"17 people bought this today"* |
| **RECURRING PAYMENT** | High | Identifies pre-selected checkboxes (`input:checked`, `[aria-checked="true"]`) containing recurring terms and payment context. | Pre-checked *"Add Premium Protection — \$4.99/month recurring subscription"* |

---

## 5. Machine Learning Text Classification

When a candidate text snippet is flagged by DOM heuristics, it is asynchronously evaluated by the backend ML classifier to corroborate dark-pattern intent.

### Model Pipeline
* **Corpus**: Yada e-commerce dark-pattern dataset containing **2,356 balanced samples** (1,178 Dark Pattern, 1,178 Not Dark Pattern).
* **Text Representation**: `TfidfVectorizer` (5,000 max features, unigrams + bigrams, English stop words removed, sublinear TF scaling).
* **Classifier**: `LogisticRegression(C=1.0, max_iter=1000, solver="lbfgs", random_state=42)`
* **Train / Test Split**: 80% training (1,884 samples) and 20% unseen testing (472 samples) with stratification.

### Evaluation Metrics
| Metric | Test Set Value |
| :--- | :---: |
| **Accuracy** | **93.01%** |
| **Precision** | **96.77%** |
| **Recall** | **88.98%** |
| **F1-Score** | **92.72%** |
| **ROC-AUC** | **97.27%** |

### Confusion Matrix (Test Split: 472 Samples)
```text
                  Predicted Negative    Predicted Positive
Actual Negative        229 (TN)               7 (FP)
Actual Positive         26 (FN)             210 (TP)
```

> [!NOTE]
> **Probabilistic Scope**: The output probability $P(\text{dark})$ represents the likelihood that the evaluated snippet resembles deceptive e-commerce language. It does **not** represent a probability that the entire website is fraudulent.

---

## 6. Scoring Methodology

FraudGuard computes two completely independent scores on a 0–100 scale. Both follow the same direction: **Higher score = safer**.

### A. Store Trust Score (0–100)
Evaluates empirical, cryptographic, and infrastructural domain credibility through direct addition of exactly four factors (no baseline, no normalization):

$$\text{Store Trust Score} = P_{\text{age}} + P_{\text{ssl}} + P_{\text{structure}} + P_{\text{whois}} \quad (\text{Max: } 100\text{ pts})$$

#### 1. Domain Age (`P_age`, Max 40 pts)
Derived from WHOIS registration creation dates:
* **> 5 years** (> 1825 days): **40 pts**
* **2 to 5 years** (730–1825 days): **35 pts**
* **1 to 2 years** (365–729 days): **30 pts**
* **181 to 364 days**: **22 pts**
* **91 to 180 days**: **15 pts**
* **30 to 90 days**: **8 pts**
* **< 30 days**: **0 pts** *(elevates overall risk via critical override)*
* **Missing / Unverified**: **0 pts** *(treated neutrally as insufficient data, not fraud)*

#### 2. SSL/TLS Health ($P_{\text{ssl}}$, Max 20 pts)
Evaluated via direct TLS socket handshake on port 443:
* **Valid certificate + Hostname verified**: **20 pts**
* **Valid certificate, but verification incomplete**: **10 pts**
* **Unable to verify / Missing data**: **0 pts**
* **Invalid / Expired / Hostname mismatch**: **0 pts** *(triggers critical override)*

#### 3. Domain Structure ($P_{\text{structure}}$, Max 20 pts)
Analyzes technical hostname characteristics:
* **Clean standard hostname (0 flags)**: **20 pts**
* **Single mild anomaly (1 flag)**: **12 pts** *(e.g., long hostname or 3 hyphens)*
* **Multiple suspicious anomalies ($\ge 2$ flags)**: **5 pts** *(triggers critical override)*
* **Punycode / Homograph (`xn--`)**: **0 pts** *(triggers critical override)*

#### 4. WHOIS / Registration Quality ($P_{\text{whois}}$, Max 20 pts)
* **Normal / Consistent registration**: **20 pts** *(accredited registrar + $\ge 2$ redundant nameservers + consistent lifecycle dates)*
* **Partial but usable registration**: **10 pts** *(registrar identified, minimal DNS redundancy)*
* **Suspicious / Restricted status**: **5 pts** *(`clientHold`, `redemptionPeriod`, `pendingDelete`)*
* **Unavailable / Privacy redacted**: **0 pts** *(privacy redactions like GDPR are never penalized as fraud)*

#### Store Trust Classification Bands
* `0 – 30`: **LOW TRUST**
* `31 – 75`: **MEDIUM TRUST**
* `76 – 100`: **HIGH TRUST**
* `null`: **INSUFFICIENT DATA**

---

### B. UI Safety Score (0–100)
Quantifies user interface safety and freedom from deceptive patterns.

#### 1. Rule Risk Evidence (`E_rules`, Max 100 pts)
* Low Severity Detection (Urgency, Scarcity, Social Proof): **+15 pts**
* Medium Severity Detection (Countdown Timers): **+25 pts**
* High Severity Detection (Recurring Charges): **+40 pts**
* Category Diversity Bonus:
  * $\ge 2$ distinct dark pattern categories: **+10 pts**
  * $\ge 3$ distinct dark pattern categories: **+15 pts**
  *(Only one diversity bonus is applied; rule risk is capped at 100)*

$$E_{\text{rules}} = \min\left(100, \sum \text{SeverityWeight}_i + \text{DiversityBonus}\right)$$

#### 2. ML Risk Evidence ($E_{\text{ml}}$, Max 100 pts)
Blends peak deceptive probability and mean probability across all evaluated text snippets:

$$E_{\text{ml}} = \min\left(100, \left(0.60 \cdot \max(P_{\text{dark}}) + 0.40 \cdot \text{avg}(P_{\text{dark}})\right) \times 100\right)$$

#### 3. Combined UI Risk ($R \in [0, 100]$)
* **When ML is available**: $R = \text{round}(0.60 \cdot E_{\text{rules}} + 0.40 \cdot E_{\text{ml}})$
* **When ML is unavailable (fallback)**: $R = \text{round}(E_{\text{rules}})$
* **When zero detections exist**: $R = 0$

#### 4. Reversal to UI Safety Score
$$\text{UI Safety Score} = 100 - R$$

* **Rule Risk / ML Risk / UI Risk**: Higher indicates more suspicious patterns.
* **UI Safety Score**: Higher indicates a safer, cleaner interface.

#### UI Safety Classification Bands
* `0 – 30`: **LOW UI SAFETY** *(Heavy deceptive manipulation)*
* `31 – 75`: **MEDIUM UI SAFETY** *(Moderate promotional pressure)*
* `76 – 100`: **HIGH UI SAFETY** *(Clean, transparent interface)*

#### Contribution Accounting Invariance
The displayed contribution breakdown strictly sums to the total displayed score:
$$\sum \text{UI Safety Contributions} = \text{UI Safety Score}$$

```text
Interface Design Safety + Language Analysis Safety == UI Safety Score
```
* **Interface Design Safety**: Up to 60 pts (with ML) or 100 pts (fallback).
* **Language Analysis Safety**: Up to 40 pts.

---

## 7. Overall Risk Assessment Engine

### A. The 9-Cell Decision Matrix (Store Trust-Priority Model)
Store Trust establishes the base risk category; UI Safety modulates the risk within that category:

| Store Trust Band | Low UI Safety (0–30) | Medium UI Safety (31–75) | High UI Safety (76–100) |
| :--- | :---: | :---: | :---: |
| **LOW TRUST (0–30)** | **HIGH RISK** | **HIGH RISK** | **MEDIUM RISK** |
| **MEDIUM TRUST (31–75)** | **HIGH RISK** | **MEDIUM RISK** | **MEDIUM RISK** |
| **HIGH TRUST (76–100)** | **MEDIUM RISK** | **LOW RISK** | **LOW RISK** |

> [!IMPORTANT]
> **The Non-Equivalence Axiom: Deceptive UI ≠ Fraud**  
> An established, legitimate e-commerce platform (High Trust) may use promotional countdown timers or scarcity badges (Low UI Safety). The matrix categorizes this as **MEDIUM RISK**, not outright fraud. Conversely, an unseasoned, newly registered storefront displaying a calm interface is categorized as **MEDIUM RISK** due to limited historical trust data.

### B. Critical Security Signal Overrides
Any of the following critical indicators overrides the matrix and deterministically escalates Overall Risk to **HIGH RISK**:
1. `CRITICAL_NEW_DOMAIN`: Domain registration age < 30 days.
2. `CRITICAL_INVALID_SSL`: Expired, self-signed, untrusted, or hostname-mismatched TLS certificate.
3. `CRITICAL_RECURRING_PAYMENT`: Pre-selected checkbox enrolling the consumer in recurring subscriptions without an affirmative opt-in click.
4. `CRITICAL_PUNYCODE_HOMOGRAPH`: Hostname uses `xn--` Punycode spoofing to impersonate known brands.
5. `CRITICAL_MULTIPLE_STRUCTURAL_FLAGS`: Hostname exhibits $\ge 2$ structural anomalies (excessive hyphens, numeric density, deep subdomains).

---

## 8. Privacy by Design

FraudGuard inspects the rendered DOM for visible UI patterns while strictly excluding sensitive user input fields:
* **Never inspected or read**:
  * Passwords (`[type="password"]`)
  * Credit card number and payment fields (`[autocomplete*="cc-"]`, `[autocomplete*="card"]`)
  * Security codes (`[autocomplete*="cvv"]`)
  * Textarea inputs (`<textarea>`)
  * General text input values (`<input type="text">`, `<input type="email">`)
  * Rich-text editable containers (`[contenteditable="true"]`)
* **Inspected elements**: Visible informational containers (`<p>`, `<span>`, `<div>`, `<label>`, `<button>`, `<li>`, headings) and checkbox selections specifically evaluated for subscription add-ons.

---

## 9. Technology Stack

* **Browser Extension**: JavaScript (ES6+), CSS3, Chrome Manifest V3 APIs (`chrome.runtime`, `chrome.storage`).
* **Backend Framework**: Python 3.10+, FastAPI, Uvicorn (ASGI server).
* **Machine Learning**: scikit-learn, NumPy, pandas, joblib.
* **Network & Security**: Python standard `ssl` and `socket` libraries, `python-whois`, `tldextract`.

---

## 10. Repository Structure

```text
FraudGuard/
├── backend/
│   ├── main.py                     # FastAPI application routes & lifecycle events
│   ├── domain_analyzer.py          # Domain normalization & structural flags
│   ├── ssl_analyzer.py             # TLS handshake & certificate verification
│   ├── whois_analyzer.py           # WHOIS querying & domain age calculation
│   ├── text_classifier.py          # ML inference loader & scoring module
│   ├── requirements.txt            # Python dependencies for backend
│   ├── test_fraudguard_all.py      # Comprehensive automated test suite
│   ├── test_server_live.py         # End-to-end live HTTP integration test
│   ├── ml/
│   │   ├── train_model.py          # ML training & evaluation pipeline
│   │   ├── model.pkl               # Serialized Logistic Regression model
│   │   ├── vectorizer.pkl          # Serialized TF-IDF vectorizer
│   │   └── metrics.json            # Model evaluation results & confusion matrix
│   └── scoring/
│       ├── scoring_engine.py       # Store Trust & UI Safety scoring logic
│       ├── risk_engine.py          # 9-cell risk matrix & critical overrides
│       ├── test_scoring.py         # Unit tests for scoring & contribution sums
│       └── __init__.py             # Scoring package exports
├── dataset/
│   └── dataset.csv                 # Cleaned e-commerce dark-pattern dataset
├── extension/
│   ├── manifest.json               # Chrome Extension Manifest V3 configuration
│   ├── background.js               # Service worker bridge to FastAPI
│   ├── content.js                  # DOM heuristic scanner, badges & drawer UI
│   ├── style.css                   # Extension styling, badge colors & animations
│   └── icons/                      # Extension icons (16px, 48px, 128px)
├── test_pages/
│   ├── test_deceptive_ui.html      # Test fixture: Urgency, scarcity, countdown
│   ├── test_suspicious_store.html  # Test fixture: Recurring payments & discounts
│   └── test_fraud_simulation.html  # Test fixture: High-intensity pressure tactics
├── RISK_METHODOLOGY.md             # Complete risk assessment technical specification
├── SCORING_METHODOLOGY.md          # Complete scoring formulas & evidence bands
├── requirements.txt                # Repository root dependencies
├── .gitignore                      # Git ignore configuration
└── README.md                       # Project documentation
```

---

## 11. Installation & Setup

### Prerequisites
* Python 3.10 or higher
* Google Chrome (or any Chromium-based browser)
* Git

### Step 1: Clone the Repository
```bash
git clone https://github.com/<your-username>/FraudGuard.git
cd FraudGuard
```

### Step 2: Set Up Python Backend Environment
```bash
# Create a virtual environment
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### Step 3: Run Backend Service
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```
The backend service will initialize, load the ML model artifacts, and print:
```text
[FraudGuard] Launched the app successfully.
INFO:     Uvicorn running on http://127.0.0.1:8001 (Press CTRL+C to quit)
```
* Interactive API Documentation (Swagger UI): [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)

### Step 4: Load Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the upper-right corner.
3. Click **Load unpacked**.
4. Select the `FraudGuard/extension/` directory.
5. The FraudGuard extension icon will now appear in your browser toolbar.

---

## 12. Testing & Verification

### Automated Backend Test Suite
Run the comprehensive integration test covering all Store Trust boundaries, UI Safety inversions, all 9 matrix cells, critical signal overrides, and contribution sum invariance:
```bash
cd backend
python test_fraudguard_all.py
```

### Scoring Engine Unit Tests
```bash
cd backend/scoring
python test_scoring.py
```

### Live End-to-End Server Verification
```bash
cd backend
python test_server_live.py
```

### Manual In-Browser Testing
1. Ensure the backend daemon is running on port 8001.
2. In Chrome, open any of the test fixtures in `test_pages/`:
   * `file:///path/to/FraudGuard/test_pages/test_deceptive_ui.html`
   * `file:///path/to/FraudGuard/test_pages/test_suspicious_store.html`
   * `file:///path/to/FraudGuard/test_pages/test_fraud_simulation.html`
3. Observe:
   * Red/Amber ⚠ warning badges dynamically attached next to manipulative elements.
   * Hovering over a badge reveals the category explanation and ML classification confidence.
   * The floating shield widget in the bottom-right updates its score and color.
   * Clicking the widget slides open the complete 7-section analytical drawer.

---

## 13. API Endpoints Reference

The FastAPI backend exposes the following endpoints on `http://127.0.0.1:8001`:

| Method | Endpoint | Description | Sample Request Payload |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Health check and subsystem readiness status | *None* |
| `GET` / `POST` | `/analyze-domain` | Normalizes hostname, queries WHOIS, and inspects SSL certificate | `{"domain": "example.com"}` |
| `GET` / `POST` | `/analyze-text` | Classifies input text into `DARK_PATTERN` or `NOT_DARK_PATTERN` | `{"text": "Only 2 left in stock!"}` |
| `POST` | `/calculate-score` | Computes Store Trust Score (0–100) and UI Safety Score (0–100) | `{"detections": [...], "domain_intelligence": {...}}` |
| `POST` | `/calculate-risk` | Evaluates 9-cell decision matrix, critical overrides, and explanations | `{"store_trust_score": 90, "ui_safety_score": 25, ...}` |

---

## 14. Example API Output

### POST `/calculate-risk`
```json
{
  "overall_risk": "MEDIUM",
  "risk_level": "MEDIUM",
  "decision_matrix_case": "HIGH_TRUST_LOW_UI_SAFETY",
  "store_trust_score": 95,
  "store_trust_level": "HIGH",
  "ui_safety_score": 26,
  "ui_safety_level": "LOW",
  "critical_signals": [],
  "significant_indicator_count": 3,
  "domain_safety_summary": "The domain appears safe based on available trust and security indicators.",
  "certificate_summary": "has a valid TLS certificate",
  "risk_guidance": "3 significant risk indicators detected. The domain has high trust, but deceptive UI patterns were detected; review findings before proceeding.",
  "risk_summary": "Store Trust is the primary factor and UI Safety is secondary. High Store Trust establishes a low base risk, but lower UI Safety indicates deceptive interface patterns, elevating the evaluation to Medium Risk.",
  "risk_reasons": [
    "✓ Primary factor — High Store Trust: established registration and valid SSL/TLS certificate establish a low base risk.",
    "⚠ Secondary factor — Low UI Safety: multiple manipulative interface patterns detected (Countdown, Scarcity, Urgency); lower UI Safety indicates stronger deceptive UI concerns.",
    "⚠ ML text classifier confirmed dark-pattern language with high probability (98%).",
    "⚖ Store Trust priority: High Store Trust establishes low base risk, but lower UI Safety modifies Overall Risk to MEDIUM RISK."
  ]
}
```

---

## 15. Limitations & Future Scope

### Limitations
1. **Context-Free NLP Window**: The ML model classifies discrete text snippets (up to 512 characters) rather than the global visual layout.
2. **Obfuscated DOM Patterns**: Novel countdown timers rendered via canvas elements or obfuscated CSS animations can evade standard DOM text queries.
3. **WHOIS Redaction**: Strict privacy protections (e.g., GDPR) can conceal domain creation timestamps, requiring fallback to SSL and DNS heuristics.

### Future Scope
* **Multimodal Visual Analysis**: Incorporate lightweight computer vision models to detect banner placement tricks and visual misdirection.
* **Broader Browser Compatibility**: Package manifest configurations for Firefox (WebExtensions) and Safari.
* **Expanded Pattern Taxonomies**: Extend coverage to sneaking add-ons, forced continuity traps, and confirm-shaming dialogues.

## 16. Project & Copyright Notice
© 2026 Niranjan S, Saswat T R, Sandhya Tiwari. All rights reserved.  
This repository is published for academic demonstration and course evaluation.
