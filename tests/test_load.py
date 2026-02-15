#!/usr/bin/env python3

import asyncio
import json
import time
import statistics
import sys
from dataclasses import dataclass, field

import aiohttp

API_BASE = "https://scamintelli.mysterysd.in/api/v1/honeypot"
API_KEY = "9RnJa8XUtHjM4PgOeeoiraRG"

SCAM_MESSAGES = [
    "WON ! You have won some lakh ! Pleaase share your bank account number to proceed !!.",
    "You won 50 lakh rupees in lucky draw! Share your bank details now to claim prize!",
    "Dear customer, your SBI account will be blocked! Update KYC immediately at this link.",
    "This is CBI officer speaking. You are under digital arrest. Transfer 2 lakh to avoid jail.",
    "Invest 10000 rupees and get 1 lakh return in 7 days! Guaranteed profit!",
    "Hello dear, I am from UK. I really love you. Please send money for flight ticket.",
    "Your computer has virus! Call Microsoft support now at 1800-XXX-XXXX to fix it!",
    "Your parcel from customs is held. Pay clearance fee of 5000 to release.",
    "Pre-approved personal loan of 10 lakh at 0% interest! Send Aadhaar to apply.",
    "We accidentally sent extra money to your UPI. Please refund 5000 immediately.",
]

BENIGN_MESSAGES = [
    "Hi, how are you doing today?",
    "Can you help me find a good restaurant nearby?",
    "The weather is nice today, perfect for a walk.",
    "I'm looking for recommendations on books to read.",
    "What time does the movie start?",
]


@dataclass
class TestResult:
    endpoint: str
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    latencies: list = field(default_factory=list)
    errors: dict = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    scam_detected_count: int = 0
    benign_count: int = 0

    @property
    def duration(self):
        return self.end_time - self.start_time

    @property
    def rps(self):
        return self.total_requests / self.duration if self.duration > 0 else 0

    def percentile(self, p):
        if not self.latencies:
            return 0
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * p / 100)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    def report(self):
        print(f"\n{'='*60}")
        print(f"  LOAD TEST RESULTS: {self.endpoint}")
        print(f"{'='*60}")
        print(f"  Total Requests:    {self.total_requests}")
        print(f"  Successful:        {self.successful} ({self.successful/self.total_requests*100:.1f}%)")
        print(f"  Failed:            {self.failed}")
        print(f"  Duration:          {self.duration:.2f}s")
        print(f"  Throughput:        {self.rps:.1f} req/s")
        if self.scam_detected_count:
            print(f"  Scam Detected:     {self.scam_detected_count}")
        if self.benign_count:
            print(f"  Benign:            {self.benign_count}")
        if self.latencies:
            print(f"\n  Latency (ms):")
            print(f"    Min:             {min(self.latencies)*1000:.1f}")
            print(f"    Mean:            {statistics.mean(self.latencies)*1000:.1f}")
            print(f"    Median (P50):    {self.percentile(50)*1000:.1f}")
            print(f"    P75:             {self.percentile(75)*1000:.1f}")
            print(f"    P90:             {self.percentile(90)*1000:.1f}")
            print(f"    P95:             {self.percentile(95)*1000:.1f}")
            print(f"    P99:             {self.percentile(99)*1000:.1f}")
            print(f"    Max:             {max(self.latencies)*1000:.1f}")
            print(f"    Std Dev:         {statistics.stdev(self.latencies)*1000:.1f}" if len(self.latencies) > 1 else "")
        if self.errors:
            print(f"\n  Errors:")
            for err, count in sorted(self.errors.items(), key=lambda x: -x[1]):
                print(f"    {err}: {count}")
        print(f"{'='*60}\n")


async def test_health(session, result, semaphore):
    async with semaphore:
        start = time.monotonic()
        try:
            async with session.get(
                f"{API_BASE}/api/v1/health",
                headers={"x-api-key": API_KEY},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                elapsed = time.monotonic() - start
                result.total_requests += 1
                result.latencies.append(elapsed)
                if resp.status == 200:
                    result.successful += 1
                else:
                    result.failed += 1
                    key = f"HTTP {resp.status}"
                    result.errors[key] = result.errors.get(key, 0) + 1
        except Exception as e:
            elapsed = time.monotonic() - start
            result.total_requests += 1
            result.failed += 1
            result.latencies.append(elapsed)
            key = type(e).__name__
            result.errors[key] = result.errors.get(key, 0) + 1


async def test_message(session, result, semaphore, request_id, messages):
    async with semaphore:
        msg = messages[request_id % len(messages)]
        payload = {
            "session_id": f"loadtest-{request_id}",
            "message": msg,
        }
        start = time.monotonic()
        try:
            async with session.post(
                f"{API_BASE}/api/v1/message",
                json=payload,
                headers={
                    "x-api-key": API_KEY,
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                elapsed = time.monotonic() - start
                result.total_requests += 1
                result.latencies.append(elapsed)
                if resp.status == 200:
                    result.successful += 1
                    data = await resp.json()
                    if data.get("scam_detected"):
                        result.scam_detected_count += 1
                    else:
                        result.benign_count += 1
                else:
                    result.failed += 1
                    key = f"HTTP {resp.status}"
                    result.errors[key] = result.errors.get(key, 0) + 1
        except Exception as e:
            elapsed = time.monotonic() - start
            result.total_requests += 1
            result.failed += 1
            result.latencies.append(elapsed)
            key = type(e).__name__
            result.errors[key] = result.errors.get(key, 0) + 1


async def run_health_test(num_requests=500, concurrency=50):
    result = TestResult(endpoint=f"GET /api/v1/health (n={num_requests}, c={concurrency})")
    semaphore = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(limit=concurrency, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        result.start_time = time.monotonic()
        tasks = [test_health(session, result, semaphore) for _ in range(num_requests)]
        await asyncio.gather(*tasks)
        result.end_time = time.monotonic()

    result.report()
    return result


async def run_message_test(num_requests=50, concurrency=10, use_scam=True):
    messages = SCAM_MESSAGES if use_scam else BENIGN_MESSAGES
    label = "SCAM" if use_scam else "BENIGN"
    result = TestResult(
        endpoint=f"POST /api/v1/message [{label}] (n={num_requests}, c={concurrency})"
    )
    semaphore = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(limit=concurrency, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        result.start_time = time.monotonic()
        tasks = [
            test_message(session, result, semaphore, i, messages)
            for i in range(num_requests)
        ]
        await asyncio.gather(*tasks)
        result.end_time = time.monotonic()

    result.report()
    return result


async def main():
    print("\n" + "=" * 60)
    print("  ScamIntelli Load Test Suite")
    print(f"  Target: {API_BASE}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Test 1: Health endpoint - high concurrency
    print("\n[1/4] Health endpoint - 500 requests, 50 concurrent...")
    await run_health_test(500, 50)

    # Test 2: Health endpoint - extreme concurrency
    print("[2/4] Health endpoint - 2000 requests, 200 concurrent...")
    await run_health_test(2000, 200)

    # Test 3: Message endpoint with scam messages
    print("[3/4] Message endpoint (SCAM) - 50 requests, 10 concurrent...")
    await run_message_test(50, 10, use_scam=True)

    # Test 4: Message endpoint with benign messages
    print("[4/4] Message endpoint (BENIGN) - 30 requests, 10 concurrent...")
    await run_message_test(30, 10, use_scam=False)

    print("\n" + "=" * 60)
    print("  ALL LOAD TESTS COMPLETE")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
