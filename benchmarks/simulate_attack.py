import sys
import os
import httpx
import time
from colorama import Fore, Style, init

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from client_simulator.fido2_signer import FIDO2ClientSimulator

init(autoreset=True)
BASE_URL = "http://127.0.0.1:8000"

def get_auth_token():
    resp = httpx.post(f"{BASE_URL}/auth/token", data={"username": "testuser", "password": "secret"})
    return resp.json()["access_token"]

def get_nonce():
    resp = httpx.get(f"{BASE_URL}/auth/nonce")
    return resp.json()["nonce"]

def register_key(simulator, token):
    httpx.post(
        f"{BASE_URL}/auth/register-key", 
        json={"credential_id": simulator.credential_id, "public_key_pem": simulator.get_public_key_pem()},
        headers={"Authorization": f"Bearer {token}"}
    )

def print_result(scenario, status, elapsed, passed):
    color = Fore.GREEN if passed else Fore.RED
    print(f"{scenario:<25} | Status: {color}{status}{Style.RESET_ALL} | Latency: {elapsed:.2f}ms | Defense Verdict: {color}{'PASS' if passed else 'FAIL'}{Style.RESET_ALL}")

def run():
    print(f"{Fore.CYAN}--- FIDO2 PoP Attack Simulation ---{Style.RESET_ALL}")
    
    try:
        token = get_auth_token()
    except Exception as e:
        print(f"{Fore.RED}Failed to connect to Gateway. Ensure run.sh is running. ({e}){Style.RESET_ALL}")
        return

    simulator = FIDO2ClientSimulator()
    register_key(simulator, token)

    # 1. Baseline
    nonce1 = get_nonce()
    headers1, _ = simulator.sign_request("GET", "/api/v1/resource", body=b"", nonce=nonce1)
    headers1["Authorization"] = f"Bearer {token}"
    
    start = time.perf_counter()
    resp1 = httpx.get(f"{BASE_URL}/api/v1/resource", headers=headers1)
    elapsed1 = (time.perf_counter() - start) * 1000
    print_result("1. Baseline", resp1.status_code, elapsed1, resp1.status_code == 200)

    # 2. Session Hijacking
    start = time.perf_counter()
    resp2 = httpx.get(f"{BASE_URL}/api/v1/resource", headers={"Authorization": f"Bearer {token}"})
    elapsed2 = (time.perf_counter() - start) * 1000
    print_result("2. Session Hijacking", resp2.status_code, elapsed2, resp2.status_code == 401)

    # 3. Replay Attack
    start = time.perf_counter()
    resp3 = httpx.get(f"{BASE_URL}/api/v1/resource", headers=headers1)
    elapsed3 = (time.perf_counter() - start) * 1000
    print_result("3. Replay Attack", resp3.status_code, elapsed3, resp3.status_code == 401)

    # 4. Body 변조 (단순)
    import hashlib
    valid_body = b'{"data": "valid"}'
    tampered_body = b'{"malicious": "payload"}'
    
    nonce4 = get_nonce()
    headers_valid, _ = simulator.sign_request("POST", "/api/v1/resource", query="", body=valid_body, nonce=nonce4)
    headers_valid["Authorization"] = f"Bearer {token}"
    
    start = time.perf_counter()
    resp4 = httpx.post(f"{BASE_URL}/api/v1/resource", headers=headers_valid, content=tampered_body)
    elapsed4 = (time.perf_counter() - start) * 1000
    print_result("4. Body 변조 (단순)", resp4.status_code, elapsed4, resp4.status_code == 400)

    # 4b. 고도화된 Body 변조 (다이제스트 조작)
    nonce4b = get_nonce()
    headers_advanced_valid, _ = simulator.sign_request("POST", "/api/v1/resource", query="", body=valid_body, nonce=nonce4b)
    headers_advanced = headers_advanced_valid.copy()
    headers_advanced["Authorization"] = f"Bearer {token}"
    headers_advanced["X-Body-Digest"] = f"sha256={hashlib.sha256(tampered_body).hexdigest()}"
    
    start = time.perf_counter()
    resp4b = httpx.post(f"{BASE_URL}/api/v1/resource", headers=headers_advanced, content=tampered_body)
    elapsed4b = (time.perf_counter() - start) * 1000
    print_result("4b. 고도화된 Body 변조", resp4b.status_code, elapsed4b, resp4b.status_code == 403)

    # 5. Path 변조
    nonce5 = get_nonce()
    headers_path, _ = simulator.sign_request("GET", "/api/v1/resource", body=b"", nonce=nonce5)
    headers_path["Authorization"] = f"Bearer {token}"
    
    start = time.perf_counter()
    resp5 = httpx.get(f"{BASE_URL}/api/v1/admin", headers=headers_path)
    elapsed5 = (time.perf_counter() - start) * 1000
    print_result("5. Path 변조", resp5.status_code, elapsed5, resp5.status_code == 403)

if __name__ == "__main__":
    run()
