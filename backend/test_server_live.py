"""
FraudGuard: Live HTTP End-to-End Server Test on Port 8001
Launches uvicorn in background, executes live HTTP requests via urllib.request,
and validates responses for health, domain analysis, text analysis, scoring, and overall risk.
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import os

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 8001
BASE_URL = f"http://127.0.0.1:{PORT}"

def wait_for_server(timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False

def run_live_tests():
    print(f"Starting uvicorn server on port {PORT}...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=BACKEND_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        print("Waiting for server to become responsive...")
        if not wait_for_server():
            print("ERROR: Server failed to start within timeout.")
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            print("Server stdout:", stdout)
            print("Server stderr:", stderr)
            sys.exit(1)

        print("[OK] Server is running!")

        # 1. Health endpoint
        print("\n--- 1. Testing GET /health ---")
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print("Health response:", data)
            assert data["status"] in ["healthy", "online"]
            assert data["ml_text_classifier"] == "ready"
            assert data["domain_intelligence"] == "ready"
            assert data["scoring_engine"] == "ready"
            assert data["risk_engine"] == "ready"

        # 2. POST /analyze-text
        print("\n--- 2. Testing POST /analyze-text ---")
        req_data = json.dumps({"text": "Hurry! Only 2 items left in stock!"}).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/analyze-text",
            data=req_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print("Prediction:", data)
            assert data["prediction"] == "DARK_PATTERN"
            assert data["confidence"] > 0.90

        # 3. Validation rejection (HTTP 400)
        print("\n--- 3. Testing POST /analyze-text empty rejection ---")
        req_empty = urllib.request.Request(
            f"{BASE_URL}/analyze-text",
            data=json.dumps({"text": "   "}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req_empty, timeout=5)
            assert False, "Should have returned 400"
        except urllib.error.HTTPError as err:
            print(f"Received expected HTTP {err.code}")
            assert err.code == 400

        # 4. GET /analyze-domain
        print("\n--- 4. Testing GET /analyze-domain ---")
        with urllib.request.urlopen(f"{BASE_URL}/analyze-domain?domain=example.com", timeout=10) as resp:
            data = json.loads(resp.read().decode())
            print("Domain:", data.get("domain"))
            print("Has SSL data:", "ssl" in data)
            assert data["domain"] == "example.com"
            assert "ssl" in data

        # 5. POST /calculate-score
        print("\n--- 5. Testing POST /calculate-score ---")
        score_payload = {
            "detections": [
                {"category": "URGENCY", "severity": "low", "message": "Hurry, only 2 left!"},
                {"category": "COUNTDOWN", "severity": "medium", "message": "Sale ends in: 00:10:00"}
            ],
            "ml_results": [
                {"prediction": "DARK_PATTERN", "confidence": 0.98, "dark_pattern_probability": 0.98}
            ],
            "domain_intelligence": data
        }
        req_score = urllib.request.Request(
            f"{BASE_URL}/calculate-score",
            data=json.dumps(score_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_score, timeout=5) as resp:
            score_data = json.loads(resp.read().decode())
            print("Scores received:", score_data)
            assert "ui_safety_score" in score_data
            assert "store_trust_score" in score_data
            assert 0 <= score_data["ui_safety_score"] <= 100
            assert score_data["ui_safety_level"] in ["LOW", "MEDIUM", "HIGH"]
            assert score_data["store_trust_level"] in ["LOW", "MEDIUM", "HIGH", "INSUFFICIENT_DATA"]
            # Verify UI Safety contribution sum equals ui_safety_score
            ui_contrib_sum = sum(c["contribution_points"] for c in score_data["ui_safety_contributions"])
            assert ui_contrib_sum == score_data["ui_safety_score"]

        # 6. POST /calculate-risk
        print("\n--- 6. Testing POST /calculate-risk ---")
        risk_payload = {
            "ui_safety_score": score_data["ui_safety_score"],
            "ui_safety_level": score_data["ui_safety_level"],
            "store_trust_score": score_data["store_trust_score"],
            "store_trust_level": score_data["store_trust_level"],
            "detections": score_payload["detections"],
            "ml_results": score_payload["ml_results"],
            "domain_intelligence": data
        }
        req_risk = urllib.request.Request(
            f"{BASE_URL}/calculate-risk",
            data=json.dumps(risk_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_risk, timeout=5) as resp:
            risk_data = json.loads(resp.read().decode())
            print("Risk assessment received:", risk_data)
            assert "overall_risk" in risk_data
            assert risk_data["overall_risk"] in ["LOW", "MEDIUM", "HIGH"]
            assert "risk_reasons" in risk_data
            assert len(risk_data["risk_reasons"]) > 0
            assert "decision_matrix_case" in risk_data

        print("\n[SUCCESS] All live HTTP server tests passed on port 8001!")

    finally:
        print("Shutting down uvicorn server...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("Server shutdown completed.")

if __name__ == "__main__":
    run_live_tests()
