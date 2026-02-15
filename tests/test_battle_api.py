"""
Battle test script matching the evaluator's exact logic from submission_guideline.txt.
Tests all 3 sample scenarios + additional edge cases against the live API.
"""
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import requests

ENDPOINT_URL = "https://scamintelli.mysterysd.in/api/v1/honeypot"
API_KEY = "9RnJa8XUtHjM4PgOeeoiraRG"

SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": (
            "URGENT: Your SBI account has been compromised. "
            "Your account will be blocked in 2 hours. Share your "
            "account number and OTP immediately to verify your identity."
        ),
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
        },
        "followUps": [
            "Your account number is 1234567890123456. Please verify NOW.",
            "Call us at +91-9876543210 urgently to save your account.",
            "Make payment via scammer.fraud@fakebank to unblock account.",
            "Time is running out! OTP is required immediately.",
            "This is final warning before legal action.",
        ],
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": (
            "Congratulations! You have won a cashback of Rs. 5000 "
            "from Paytm. To claim your reward, please verify your "
            "UPI details. This is from official customer support."
        ),
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
        },
        "followUps": [
            "Please send Rs 99 to cashback.scam@fakeupi to process your reward.",
            "Call our verification helpline +91-8765432109.",
            "Your reward expires in 5 minutes! Act fast!",
            "Sir ji jaldi karo, ye limited offer hai.",
            "Last chance to claim your Rs 5000 cashback!",
        ],
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": (
            "You have been selected for iPhone 15 Pro at just Rs. 999! "
            "Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. "
            "Offer expires in 10 minutes!"
        ),
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
        },
        "followUps": [
            "For queries email offers@fake-amazon-deals.com.",
            "Hurry! Only 3 iPhones left at this price!",
            "Click http://amaz0n-deals.fake-site.com/claim?id=12345 now!",
            "This is a verified offer from Amazon partner program.",
        ],
    },
    {
        "scenarioId": "digital_arrest",
        "name": "Digital Arrest Scam",
        "scamType": "digital_arrest",
        "initialMessage": (
            "This is CBI calling. An FIR has been filed against your "
            "Aadhaar number for money laundering. You are under digital "
            "arrest. Do not disconnect or you will be arrested."
        ),
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "phoneNumber": "+91-7777888899",
        },
        "followUps": [
            "Your Aadhaar is linked to terrorism funding.",
            "Transfer Rs 50,000 to clear your name. Call +91-7777888899.",
            "FIR number BOM-2025-CBI-99999.",
            "This is Inspector Verma from CBI Cyber Cell.",
            "If you disconnect, we will send police to your address.",
        ],
    },
    {
        "scenarioId": "hinglish_scam",
        "name": "Hinglish Investment Scam",
        "scamType": "investment_fraud",
        "initialMessage": (
            "Bhai mere paas ek guaranteed investment plan hai. "
            "Daily 5% return milega. Bas Rs 10,000 invest karo "
            "aur agle mahine 1 lakh kamao. Koi risk nahi hai."
        ),
        "metadata": {"channel": "WhatsApp", "language": "Hinglish", "locale": "IN"},
        "maxTurns": 10,
        "fakeData": {
            "upiId": "invest.guru@oksbi",
            "phoneNumber": "+91-6543219876",
        },
        "followUps": [
            "Paisa bhejo invest.guru@oksbi par.",
            "Call karo +91-6543219876 pe details ke liye.",
            "100% safe hai bhai, trust karo.",
            "Bahut log already kamaa rahe hain.",
        ],
    },
]

KEY_MAPPING = {
    "bankAccount": "bankAccounts",
    "upiId": "upiIds",
    "phoneNumber": "phoneNumbers",
    "phishingLink": "phishingLinks",
    "emailAddress": "emailAddresses",
}


def evaluate_response(response_data, scenario, conversation_history):
    """Evaluate using the same logic as the evaluator."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    if response_data.get("scamDetected", False):
        score["scamDetection"] = 20

    extracted = response_data.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})

    for fake_key, fake_value in fake_data.items():
        output_key = KEY_MAPPING.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score["intelligenceExtraction"] += 10

    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    metrics = response_data.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)

    if duration > 0:
        score["engagementQuality"] += 5
    if duration > 60:
        score["engagementQuality"] += 5
    if messages > 0:
        score["engagementQuality"] += 5
    if messages >= 5:
        score["engagementQuality"] += 5

    if "status" in response_data:
        score["responseStructure"] += 5
    if "scamDetected" in response_data:
        score["responseStructure"] += 5
    if "extractedIntelligence" in response_data:
        score["responseStructure"] += 5
    if response_data.get("engagementMetrics"):
        score["responseStructure"] += 2.5
    if response_data.get("agentNotes"):
        score["responseStructure"] += 2.5

    score["responseStructure"] = min(score["responseStructure"], 20)
    score["total"] = sum(score.values())
    return score


def run_scenario(scenario):
    """Run a full multi-turn scenario matching evaluator behavior."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
    }
    last_response = None

    messages_to_send = [scenario["initialMessage"]] + scenario.get("followUps", [])
    turns = min(len(messages_to_send), scenario["maxTurns"])

    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario['name']} ({scenario['scenarioId']})")
    print(f"Expected scamType: {scenario['scamType']}")
    print(f"FakeData: {json.dumps(scenario['fakeData'], indent=2)}")
    print(f"{'='*70}")

    for turn in range(turns):
        scammer_msg = messages_to_send[turn]
        message = {
            "sender": "scammer",
            "text": scammer_msg,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"],
        }

        print(f"\n--- Turn {turn + 1}/{turns} ---")
        print(f"  Scammer: {scammer_msg[:80]}...")

        try:
            start = time.time()
            response = requests.post(
                ENDPOINT_URL,
                headers=headers,
                json=request_body,
                timeout=30,
            )
            elapsed = time.time() - start

            if response.status_code != 200:
                print(f"  ERROR: status {response.status_code}: {response.text[:200]}")
                return None

            data = response.json()
            last_response = data
            reply = data.get("reply") or data.get("message") or data.get("text", "")

            print(f"  Honeypot: {reply[:80]}...")
            print(f"  scamDetected={data.get('scamDetected')}, "
                  f"scamType={data.get('scamType')}, "
                  f"latency={elapsed:.2f}s")

            intel = data.get("extractedIntelligence", {})
            has_intel = any(
                intel.get(k) for k in
                ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]
            )
            if has_intel:
                print(f"  Intel extracted: {json.dumps(intel, indent=4)}")

            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        except requests.exceptions.Timeout:
            print("  ERROR: Request timeout (>30s)")
            return None
        except Exception as e:
            print(f"  ERROR: {e}")
            return None

    if last_response:
        score = evaluate_response(last_response, scenario, conversation_history)
        print(f"\n  SCORE: {score['total']}/100")
        print(f"    Detection: {score['scamDetection']}/20")
        print(f"    Intel:     {score['intelligenceExtraction']}/40")
        print(f"    Engage:    {score['engagementQuality']}/20")
        print(f"    Structure: {score['responseStructure']}/20")
        return score

    return None


def main():
    print("ScamIntelli Battle Test")
    print(f"Endpoint: {ENDPOINT_URL}")
    print(f"API Key:  {API_KEY[:6]}...")

    # Health check
    try:
        r = requests.get(
            "https://scamintelli.mysterysd.in/api/v1/health", timeout=10
        )
        print(f"Health: {r.json()}")
    except Exception as e:
        print(f"Health check failed: {e}")
        sys.exit(1)

    all_scores = []
    for scenario in SCENARIOS:
        score = run_scenario(scenario)
        if score:
            all_scores.append({"scenario": scenario["name"], **score})

    print("\n" + "=" * 70)
    print("BATTLE TEST SUMMARY")
    print("=" * 70)

    total_overall = 0
    for s in all_scores:
        print(f"  {s['scenario']:40s} => {s['total']}/100")
        total_overall += s["total"]

    avg = total_overall / max(len(all_scores), 1)
    print(f"\n  AVERAGE SCORE: {avg:.1f}/100")
    print(f"  SCENARIOS RUN: {len(all_scores)}/{len(SCENARIOS)}")

    return 0 if avg >= 60 else 1


if __name__ == "__main__":
    sys.exit(main())
