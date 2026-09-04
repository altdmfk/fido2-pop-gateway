import os
import sys
import httpx
import time
import json
import base64

# Ensure the root project directory is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client_simulator.fido2_signer import FIDO2ClientSimulator
from client_simulator.rsa_signer import RSAPoPClientSimulator

BASE_URL = "http://127.0.0.1:8000"
ITERATIONS = 100

def get_auth_token():
    resp = httpx.post(f"{BASE_URL}/auth/token", data={"username": "testuser", "password": "secret"})
    return resp.json()["access_token"]

def get_nonce():
    resp = httpx.get(f"{BASE_URL}/auth/nonce")
    return resp.json()["nonce"]

def register_key(simulator, token):
    resp = httpx.post(
        f"{BASE_URL}/auth/register-key", 
        json={"credential_id": simulator.credential_id, "public_key_pem": simulator.get_public_key_pem()},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, f"Registration failed: {resp.text}"

def calc_stats(latencies):
    latencies.sort()
    mean = sum(latencies) / len(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    return mean, p95

def get_payload_size(headers):
    # Sum of bytes for signature and other PoP headers
    return sum(len(k.encode()) + len(v.encode()) for k, v in headers.items() if k.startswith("X-FIDO2-"))

def benchmark():
    try:
        token = get_auth_token()
    except Exception as e:
        print(f"Failed to connect to Gateway. Ensure the server is running. ({e})")
        return

    client = httpx.Client()
    
    # Warmup
    client.get(f"{BASE_URL}/api/v1/baseline-jwt", headers={"Authorization": f"Bearer {token}"})

    # --- Mode A: Standard Bearer JWT ---
    print("Running Mode A (Standard Bearer JWT)...")
    latencies_a = []
    size_a = 0
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        resp = client.get(f"{BASE_URL}/api/v1/baseline-jwt", headers={"Authorization": f"Bearer {token}"})
        latencies_a.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200

    # --- Mode B: RSA-2048 / RS256 PoP ---
    print("Running Mode B (RSA-2048 / RS256 PoP)...")
    rsa_simulator = RSAPoPClientSimulator()
    register_key(rsa_simulator, token)
    latencies_b = []
    sample_headers_b = None
    for _ in range(ITERATIONS):
        nonce = get_nonce()
        headers, _ = rsa_simulator.sign_request("GET", "/api/v1/resource", b"", nonce)
        if not sample_headers_b: sample_headers_b = headers
        headers["Authorization"] = f"Bearer {token}"
        
        start = time.perf_counter()
        resp = client.get(f"{BASE_URL}/api/v1/resource", headers=headers)
        latencies_b.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200, f"Mode B failed: {resp.text}"

    # --- Mode C: ECDSA P-256 / ES256 PoP ---
    print("Running Mode C (ECDSA P-256 / ES256 PoP)...")
    ec_simulator = FIDO2ClientSimulator()
    register_key(ec_simulator, token)
    latencies_c = []
    sample_headers_c = None
    for _ in range(ITERATIONS):
        nonce = get_nonce()
        headers, _ = ec_simulator.sign_request("GET", "/api/v1/resource", b"", nonce)
        if not sample_headers_c: sample_headers_c = headers
        headers["Authorization"] = f"Bearer {token}"
        
        start = time.perf_counter()
        resp = client.get(f"{BASE_URL}/api/v1/resource", headers=headers)
        latencies_c.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200

    mean_a, p95_a = calc_stats(latencies_a)
    mean_b, p95_b = calc_stats(latencies_b)
    mean_c, p95_c = calc_stats(latencies_c)

    size_b = get_payload_size(sample_headers_b)
    size_c = get_payload_size(sample_headers_c)

    overhead_b_vs_a = ((mean_b - mean_a) / mean_a) * 100 if mean_a > 0 else 0
    overhead_c_vs_a = ((mean_c - mean_a) / mean_a) * 100 if mean_a > 0 else 0

    # --- CLI ASCII Table ---
    print("\n" + "="*85)
    print(f"{'Mode':<30} | {'Mean (ms)':<10} | {'P95 (ms)':<10} | {'Payload (B)':<11} | {'Overhead (%)':<12}")
    print("-" * 85)
    print(f"{'Mode A (Bearer JWT)':<30} | {mean_a:<10.2f} | {p95_a:<10.2f} | {size_a:<11} | {'Baseline':<12}")
    print(f"{'Mode B (RSA-2048 PoP)':<30} | {mean_b:<10.2f} | {p95_b:<10.2f} | {size_b:<11} | {overhead_b_vs_a:+.2f}%")
    print(f"{'Mode C (ECDSA P-256 PoP)':<30} | {mean_c:<10.2f} | {p95_c:<10.2f} | {size_c:<11} | {overhead_c_vs_a:+.2f}%")
    print("=" * 85)

    # --- JSON Results ---
    results = {
        "iterations": ITERATIONS,
        "mode_a_jwt_only": {
            "mean_ms": round(mean_a, 2),
            "p95_ms": round(p95_a, 2),
            "payload_bytes": size_a
        },
        "mode_b_rsa2048_pop": {
            "mean_ms": round(mean_b, 2),
            "p95_ms": round(p95_b, 2),
            "payload_bytes": size_b,
            "relative_overhead_pct": round(overhead_b_vs_a, 2)
        },
        "mode_c_ecdsa_p256_pop": {
            "mean_ms": round(mean_c, 2),
            "p95_ms": round(p95_c, 2),
            "payload_bytes": size_c,
            "relative_overhead_pct": round(overhead_c_vs_a, 2)
        }
    }

    with open("docs/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("\nSaved robust comparison results to docs/benchmark_results.json")

if __name__ == "__main__":
    benchmark()
