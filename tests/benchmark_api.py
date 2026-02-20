#!/usr/bin/env python3
"""
Benchmark script for ScamIntelli API — measures response time, throughput, and
quality across multi-turn conversations and concurrent sessions.
"""
import json
import time
import uuid
import statistics
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost/api/v1"
API_KEY = "9RnJa8XUtHjM4PgOeeoiraRG"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}
TIMEOUT = 30

# ── Scam scenarios for multi-turn test ──────────────────────────────────────
SCAM_TURNS = [
    "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity. Call us at +91-9876543210.",
    "I am calling from SBI fraud department. My employee ID is SBI-12345. We detected suspicious transactions on your account ending in 7890. You need to verify now or your account will be permanently frozen.",
    "Sir, please share the 6-digit OTP sent to your mobile. This is for security verification only. I am authorized officer Rajesh Kumar from the cyber fraud cell.",
    "Sir time is running out. If you don't verify in next 5 minutes, we will have to file an FIR against you. Your Aadhaar-linked account shows Rs 4,50,000 unauthorized transfer.",
    "I understand your concern sir. You can verify my identity - my badge number is CF-2024-7891. Please download our verification app from http://sbi-secure-verify.fake.com and enter your details.",
    "Sir we are trying to HELP you. The RBI has flagged your account. Please transfer Rs 10,000 as security deposit to UPI ID: fraud.verify@paytm to unfreeze your account.",
    "This is your last chance sir. I am escalating to the cyber crime branch. Inspector Sharma will call you. Share your PAN card number and date of birth for records.",
    "Sir, Inspector Sharma here from Cyber Crime Branch. Case number CC-2024-56789. Your bank account 1234567890123456 is under investigation. Cooperate or face arrest under Section 420 IPC.",
    "We have arrested 15 people in this case already. You need to prove your innocence. Transfer the security amount to our official account: scammer@fakebank UPI. This is mandatory.",
    "Final warning. Non-cooperation will lead to immediate arrest warrant. Verify your identity at our portal: http://police-verify-india.fake.com/kyc. Your case will be closed once verified.",
]


def make_request(session_id: str, message: str, history: list) -> dict:
    """Send a single honeypot request and return timing + response data."""
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": message,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "conversationHistory": history,
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
    }
    start = time.perf_counter()
    resp = requests.post(f"{BASE_URL}/honeypot", headers=HEADERS, json=payload, timeout=TIMEOUT)
    elapsed = time.perf_counter() - start
    data = resp.json()
    return {"elapsed": elapsed, "status": resp.status_code, "data": data}


def run_multi_turn_test():
    """Run a full 10-turn conversation and measure per-turn latency."""
    print("\n" + "=" * 70)
    print("  MULTI-TURN CONVERSATION TEST (10 turns)")
    print("=" * 70)
    
    session_id = f"bench-multi-{uuid.uuid4().hex[:8]}"
    history = []
    turn_times = []
    
    for i, scam_msg in enumerate(SCAM_TURNS, 1):
        result = make_request(session_id, scam_msg, history)
        elapsed = result["elapsed"]
        turn_times.append(elapsed)
        data = result["data"]
        
        reply = data.get("reply", "NO REPLY")
        scam = data.get("scamDetected", False)
        intel = data.get("extractedIntelligence", {})
        flags_count = len(data.get("redFlagsDetail", []))
        has_question = "?" in reply
        reply_len = len(reply)
        
        # Count extracted intel items
        intel_count = sum(len(v) for v in intel.values() if isinstance(v, list))
        
        print(f"\n  Turn {i:2d} | {elapsed:.3f}s | scam={scam} | intel={intel_count} | flags={flags_count} | ?={has_question} | len={reply_len}")
        print(f"    Reply: {reply[:120]}{'...' if len(reply) > 120 else ''}")
        
        # Build history
        history.append({"sender": "scammer", "text": scam_msg, "timestamp": str(int(time.time() * 1000))})
        history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})
    
    # Final output summary
    final = data
    print("\n" + "-" * 70)
    print("  FINAL OUTPUT ANALYSIS:")
    print(f"    scamDetected:       {final.get('scamDetected')}")
    print(f"    scamType:           {final.get('scamType')}")
    print(f"    confidenceLevel:    {final.get('confidenceLevel')}")
    print(f"    totalMessages:      {final.get('totalMessagesExchanged')}")
    print(f"    engagementDuration: {final.get('engagementDurationSeconds')}s")
    
    intel_final = final.get("extractedIntelligence", {})
    print(f"    Extracted Intel:")
    for k, v in intel_final.items():
        if v:
            print(f"      {k}: {v}")
    
    flags = final.get("redFlagsDetail", [])
    flag_types = list(set(f.get("type", "") for f in flags))
    print(f"    Red Flags ({len(flags)}): {', '.join(flag_types[:10])}")
    
    print(f"\n  LATENCY STATS ({len(turn_times)} turns):")
    print(f"    Min:    {min(turn_times):.3f}s")
    print(f"    Max:    {max(turn_times):.3f}s")
    print(f"    Mean:   {statistics.mean(turn_times):.3f}s")
    print(f"    Median: {statistics.median(turn_times):.3f}s")
    print(f"    P95:    {sorted(turn_times)[int(len(turn_times) * 0.95)]:.3f}s")
    print(f"    Total:  {sum(turn_times):.3f}s")
    
    return turn_times


def run_concurrent_throughput_test(num_sessions=5, turns_per_session=3):
    """Measure throughput with concurrent sessions."""
    print("\n" + "=" * 70)
    print(f"  CONCURRENT THROUGHPUT TEST ({num_sessions} sessions × {turns_per_session} turns)")
    print("=" * 70)
    
    scam_messages = SCAM_TURNS[:turns_per_session]
    
    def run_session(idx):
        sid = f"bench-conc-{idx}-{uuid.uuid4().hex[:8]}"
        history = []
        times = []
        for msg in scam_messages:
            result = make_request(sid, msg, history)
            times.append(result["elapsed"])
            reply = result["data"].get("reply", "")
            history.append({"sender": "scammer", "text": msg, "timestamp": str(int(time.time() * 1000))})
            history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})
        return {"session": idx, "times": times, "total": sum(times)}
    
    all_times = []
    session_results = []
    
    wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=num_sessions) as pool:
        futures = {pool.submit(run_session, i): i for i in range(num_sessions)}
        for f in as_completed(futures):
            r = f.result()
            session_results.append(r)
            all_times.extend(r["times"])
    wall_elapsed = time.perf_counter() - wall_start
    
    total_requests = num_sessions * turns_per_session
    
    for r in sorted(session_results, key=lambda x: x["session"]):
        ts = " | ".join(f"{t:.3f}s" for t in r["times"])
        print(f"    Session {r['session']}: {ts} (total {r['total']:.3f}s)")
    
    print(f"\n  CONCURRENT THROUGHPUT STATS:")
    print(f"    Total requests:   {total_requests}")
    print(f"    Wall clock time:  {wall_elapsed:.3f}s")
    print(f"    Throughput:       {total_requests / wall_elapsed:.2f} req/s")
    print(f"    Avg latency:      {statistics.mean(all_times):.3f}s")
    print(f"    P50 latency:      {statistics.median(all_times):.3f}s")
    print(f"    P95 latency:      {sorted(all_times)[int(len(all_times) * 0.95)]:.3f}s")
    print(f"    Max latency:      {max(all_times):.3f}s")
    
    return all_times, wall_elapsed


def run_rapid_fire_test(num_requests=20):
    """Rapid sequential requests to measure sustained throughput."""
    print("\n" + "=" * 70)
    print(f"  RAPID-FIRE SEQUENTIAL TEST ({num_requests} requests)")
    print("=" * 70)
    
    msg = "URGENT: Your account has been compromised. Share OTP now. Call +91-1234567890."
    times = []
    errors = 0
    
    for i in range(num_requests):
        sid = f"bench-rapid-{uuid.uuid4().hex[:8]}"
        try:
            result = make_request(sid, msg, [])
            times.append(result["elapsed"])
            if result["status"] != 200:
                errors += 1
        except Exception as e:
            errors += 1
            print(f"    Request {i+1}: ERROR - {e}")
    
    if times:
        print(f"\n  RAPID-FIRE STATS:")
        print(f"    Successful:  {len(times)}/{num_requests}")
        print(f"    Errors:      {errors}")
        print(f"    Min:         {min(times):.3f}s")
        print(f"    Max:         {max(times):.3f}s")
        print(f"    Mean:        {statistics.mean(times):.3f}s")
        print(f"    Median:      {statistics.median(times):.3f}s")
        print(f"    Total:       {sum(times):.3f}s")
        print(f"    Throughput:  {len(times) / sum(times):.2f} req/s")
    
    return times


def scoring_checklist(final_data):
    """Check how the final response scores against the rubric."""
    print("\n" + "=" * 70)
    print("  SCORING CHECKLIST (vs submission_guide_up.txt)")
    print("=" * 70)
    
    score = 0
    
    # 1. Scam Detection (20 pts)
    sd = final_data.get("scamDetected", False)
    pts = 20 if sd else 0
    score += pts
    print(f"  [{'✓' if sd else '✗'}] Scam Detection: {pts}/20")
    
    # 2. Extracted Intelligence (30 pts) - check key types
    intel = final_data.get("extractedIntelligence", {})
    extracted_types = [k for k, v in intel.items() if v and isinstance(v, list) and len(v) > 0]
    # Can't calculate exact score without knowing scenario fake data, but count types
    print(f"  [i] Intel types extracted: {len(extracted_types)} ({', '.join(extracted_types)})")
    
    # 3. Conversation Quality (30 pts)
    msgs = final_data.get("totalMessagesExchanged", 0)
    turns = msgs // 2  # approximate
    turn_pts = 8 if turns >= 8 else (6 if turns >= 6 else (3 if turns >= 4 else 0))
    score += turn_pts
    print(f"  [{'✓' if turns >= 8 else '~'}] Turn count: {turns} → {turn_pts}/8 pts")
    
    flags = final_data.get("redFlagsDetail", [])
    flag_types = list(set(f.get("type", "") for f in flags))
    flag_pts = 8 if len(flag_types) >= 5 else (5 if len(flag_types) >= 3 else (2 if len(flag_types) >= 1 else 0))
    score += flag_pts
    print(f"  [{'✓' if len(flag_types) >= 5 else '~'}] Red flags: {len(flag_types)} unique types → {flag_pts}/8 pts")
    
    # 4. Engagement (10 pts)
    duration = final_data.get("engagementDurationSeconds", 0)
    eng_pts = 0
    if duration > 0: eng_pts += 1
    if duration > 60: eng_pts += 2
    if duration > 180: eng_pts += 1
    if msgs > 0: eng_pts += 2
    if msgs >= 5: eng_pts += 3
    if msgs >= 10: eng_pts += 1
    score += eng_pts
    print(f"  [{'✓' if eng_pts >= 8 else '~'}] Engagement: duration={duration}s, msgs={msgs} → {eng_pts}/10 pts")
    
    # 5. Response Structure (10 pts)
    struct_pts = 0
    for field, pts_val in [("sessionId", 2), ("scamDetected", 2), ("extractedIntelligence", 2),
                            ("totalMessagesExchanged", 0.5), ("engagementDurationSeconds", 0.5),
                            ("agentNotes", 1), ("scamType", 1), ("confidenceLevel", 1)]:
        present = field in final_data and final_data[field] is not None
        struct_pts += pts_val if present else 0
    score += struct_pts
    print(f"  [{'✓' if struct_pts >= 9 else '~'}] Structure: {struct_pts}/10 pts")
    
    print(f"\n  ESTIMATED SCORE: {score}/78 (excl. intel 30pts + questions scoring)")
    print(f"  Note: Intel score depends on scenario-specific fake data matching.")


if __name__ == "__main__":
    print("\n" + "█" * 70)
    print("  ScamIntelli API Benchmark")
    print("█" * 70)
    
    # 1. Multi-turn test
    turn_times = run_multi_turn_test()
    
    # Check scoring on the last response
    sid = f"bench-score-{uuid.uuid4().hex[:8]}"
    history = []
    last_data = None
    for msg in SCAM_TURNS:
        result = make_request(sid, msg, history)
        last_data = result["data"]
        reply = last_data.get("reply", "")
        history.append({"sender": "scammer", "text": msg, "timestamp": str(int(time.time() * 1000))})
        history.append({"sender": "user", "text": reply, "timestamp": str(int(time.time() * 1000))})
    
    scoring_checklist(last_data)
    
    # 2. Concurrent test
    conc_times, wall = run_concurrent_throughput_test(num_sessions=5, turns_per_session=3)
    
    # 3. Rapid-fire test
    rapid_times = run_rapid_fire_test(num_requests=20)
    
    # Summary
    print("\n" + "█" * 70)
    print("  OVERALL SUMMARY")
    print("█" * 70)
    all_times = turn_times + conc_times + rapid_times
    print(f"    Total requests benchmarked: {len(all_times)}")
    print(f"    Overall mean latency:       {statistics.mean(all_times):.3f}s")
    print(f"    Overall median latency:     {statistics.median(all_times):.3f}s")
    print(f"    Overall P95 latency:        {sorted(all_times)[int(len(all_times) * 0.95)]:.3f}s")
    print(f"    Overall max latency:        {max(all_times):.3f}s")
    
    # Pass/fail criteria
    mean_lat = statistics.mean(all_times)
    p95_lat = sorted(all_times)[int(len(all_times) * 0.95)]
    if mean_lat < 5.0 and p95_lat < 15.0:
        print(f"\n    ✅ PASS: Mean {mean_lat:.3f}s < 5s, P95 {p95_lat:.3f}s < 15s")
    elif mean_lat < 10.0:
        print(f"\n    ⚠️  WARN: Mean {mean_lat:.3f}s (target < 5s)")
    else:
        print(f"\n    ❌ FAIL: Mean {mean_lat:.3f}s exceeds 10s target")
    print()
