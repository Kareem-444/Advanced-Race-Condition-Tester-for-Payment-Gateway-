#!/usr/bin/env python3
"""
Advanced Race Condition Tester v3.0 - Enterprise Edition
Professional security testing tool for payment gateway vulnerability assessment
Authorized use only - for security testing in controlled environments
"""

import asyncio
import aiohttp
import time
import argparse
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import random
import sys
from pathlib import Path

try:
    from tqdm import tqdm
    from tqdm.asyncio import tqdm as async_tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("[!] tqdm not installed. Install with: pip install tqdm")
    print("[!] Progress bars will be disabled\n")

# Configure logging
def setup_logging(log_file: Optional[str] = None, verbose: bool = False):
    """Setup comprehensive logging system"""
    if log_file is None:
        log_file = f"race_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter('%(levelname)s: %(message)s')
    
    # File handler (detailed)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler (simple)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return log_file

logger = logging.getLogger(__name__)

@dataclass
class EndpointConfig:
    """Configuration for a single endpoint"""
    url: str
    method: str = "POST"
    payload_template: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None

@dataclass
class TestConfig:
    """Enhanced configuration for race condition testing"""
    target_url: str
    balance_url: Optional[str] = None
    auth_token: str = "YOUR_TEST_TOKEN"
    amount: float = 100.0
    concurrent_requests: int = 50
    timeout: int = 10
    proxy: Optional[str] = None
    proxy_list: Optional[List[str]] = None
    retry_attempts: int = 1
    jitter_ms: int = 0
    verify_balance: bool = False
    delay_before_race: float = 0.0
    use_http2: bool = False
    connection_reuse: bool = True
    warm_up: bool = True
    rate_limit_retry: bool = True
    rate_limit_max_retries: int = 3
    rate_limit_backoff: float = 1.0
    multi_endpoint: bool = False
    secondary_endpoints: List[EndpointConfig] = field(default_factory=list)
    auto_adjust_concurrency: bool = False
    
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
    transaction_id: Optional[str] = None
    proxy_used: Optional[str] = None
    endpoint_url: Optional[str] = None
    retry_count: int = 0

@dataclass
class BalanceSnapshot:
    """Balance information at a point in time"""
    balance: float
    timestamp: datetime
    raw_response: Dict[Any, Any]

class RaceConditionTester:
    """Enterprise-grade race condition tester"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.results: List[TestResult] = []
        self.csrf_token: Optional[str] = None
        self.session_cookies: Optional[aiohttp.CookieJar] = None
        self.balance_before: Optional[BalanceSnapshot] = None
        self.balance_after: Optional[BalanceSnapshot] = None
        self.connection_established = False
        self.proxy_pool = []
        self.rate_limit_detected = False
        
        if config.proxy_list:
            self.proxy_pool = config.proxy_list.copy()
            random.shuffle(self.proxy_pool)
            logger.info(f"Loaded {len(self.proxy_pool)} proxies for distributed testing")
        elif config.proxy:
            self.proxy_pool = [config.proxy]
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy from pool (round-robin)"""
        if not self.proxy_pool:
            return None
        proxy = self.proxy_pool.pop(0)
        self.proxy_pool.append(proxy)  # Rotate
        return proxy
    
    def deep_search_balance(self, data: Any, visited: set = None) -> Optional[float]:
        """Recursively search for balance in nested structures"""
        if visited is None:
            visited = set()
        
        if id(data) in visited:
            return None
        visited.add(id(data))
        
        balance_keys = ['balance', 'amount', 'available_balance', 'current_balance', 
                       'value', 'total', 'funds', 'available', 'wallet_balance']
        
        if isinstance(data, dict):
            # Direct key match
            for key in balance_keys:
                if key in data:
                    try:
                        return float(data[key])
                    except (ValueError, TypeError):
                        pass
            
            # Recursive search
            for value in data.values():
                result = self.deep_search_balance(value, visited)
                if result is not None:
                    return result
        
        elif isinstance(data, list) and data:
            # Check first item
            return self.deep_search_balance(data[0], visited)
        
        return None
    
    async def warm_up_connection(self, session: aiohttp.ClientSession):
        """Establish and warm up connections"""
        if not self.config.warm_up:
            return
        
        logger.info("Warming up connections...")
        try:
            headers = {
                "Authorization": f"Bearer {self.config.auth_token}",
                "Content-Type": "application/json"
            }
            
            warm_up_count = min(5, self.config.concurrent_requests // 10)
            for i in range(warm_up_count):
                try:
                    async with session.options(
                        self.config.target_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        pass
                except Exception as e:
                    logger.debug(f"Warm-up request {i+1} failed: {e}")
                await asyncio.sleep(0.05)
            
            logger.info(f"Connection pool warmed up with {warm_up_count} requests")
            self.connection_established = True
        except Exception as e:
            logger.warning(f"Warm-up warning: {e}")
    
    async def get_balance(self, session: aiohttp.ClientSession) -> Optional[BalanceSnapshot]:
        """Fetch current balance with enhanced detection"""
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
                
                # Deep search for balance
                balance = self.deep_search_balance(data)
                
                if balance is None:
                    logger.warning(f"Could not find balance in response: {data}")
                    return None
                
                logger.debug(f"Balance retrieved: {balance}")
                return BalanceSnapshot(
                    balance=balance,
                    timestamp=datetime.now(),
                    raw_response=data
                )
        except Exception as e:
            logger.error(f"Error fetching balance: {e}")
            return None
    
    async def get_csrf_token(self, session: aiohttp.ClientSession) -> Optional[str]:
        """Retrieve CSRF token with multiple strategies"""
        headers = {
            "Authorization": f"Bearer {self.config.auth_token}",
            "Content-Type": "application/json"
        }
        
        csrf_keys = ['csrf_token', 'token', 'csrfToken', '_token', 'csrf', 
                    'xsrf_token', 'authenticity_token', 'anti_csrf_token']
        csrf_headers = ['X-CSRF-Token', 'X-XSRF-Token', 'CSRF-Token', 'X-CSRF-TOKEN']
        
        # Strategy 1: GET request
        try:
            async with session.get(
                self.config.target_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                # Check response body
                try:
                    data = await response.json()
                    for key in csrf_keys:
                        if key in data:
                            logger.info(f"CSRF token found in response body: {key}")
                            return data[key]
                except:
                    pass
                
                # Check headers
                for header in csrf_headers:
                    if header in response.headers:
                        logger.info(f"CSRF token found in header: {header}")
                        return response.headers[header]
        except Exception as e:
            logger.debug(f"GET strategy failed: {e}")
        
        # Strategy 2: OPTIONS request
        try:
            async with session.options(
                self.config.target_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                for header in csrf_headers:
                    if header in response.headers:
                        logger.info(f"CSRF token found via OPTIONS: {header}")
                        return response.headers[header]
        except:
            pass
        
        logger.info("No CSRF token found (may not be required)")
        return None
    
    async def send_transaction_with_retry(self, session: aiohttp.ClientSession,
                                         request_id: int, trigger_event: asyncio.Event,
                                         endpoint_config: Optional[EndpointConfig] = None) -> TestResult:
        """Send transaction with automatic rate limit handling"""
        max_retries = self.config.rate_limit_max_retries if self.config.rate_limit_retry else 0
        
        for retry in range(max_retries + 1):
            result = await self.send_transaction(session, request_id, trigger_event, 
                                                endpoint_config, retry_count=retry)
            
            # Check for rate limiting
            if result.status_code == 429 and retry < max_retries:
                self.rate_limit_detected = True
                backoff = self.config.rate_limit_backoff * (2 ** retry)
                logger.warning(f"Rate limit detected (429). Retrying in {backoff:.2f}s... (attempt {retry+1}/{max_retries})")
                await asyncio.sleep(backoff)
                continue
            
            return result
        
        return result
    
    async def send_transaction(self, session: aiohttp.ClientSession, 
                               request_id: int, trigger_event: asyncio.Event,
                               endpoint_config: Optional[EndpointConfig] = None,
                               retry_count: int = 0) -> TestResult:
        """Send a single transaction request with advanced optimization"""
        
        # Select proxy for this request
        proxy = self.get_next_proxy() if len(self.proxy_pool) > 1 else (self.proxy_pool[0] if self.proxy_pool else None)
        
        # Jitter before waiting
        if self.config.jitter_ms > 0:
            jitter = random.uniform(0, self.config.jitter_ms / 1000.0)
            await asyncio.sleep(jitter)
        
        # Wait for trigger - all requests synchronized here
        await trigger_event.wait()
        
        # Start precise timing
        start_time = time.perf_counter()
        
        # Determine endpoint
        if endpoint_config:
            url = endpoint_config.url
            method = endpoint_config.method
            custom_headers = endpoint_config.headers or {}
        else:
            url = self.config.target_url
            method = "POST"
            custom_headers = {}
        
        headers = {
            "Authorization": f"Bearer {self.config.auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            **custom_headers
        }
        
        # Add CSRF token
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
            headers["X-XSRF-Token"] = self.csrf_token
        
        # Generate unique identifiers
        unique_id = f"{int(time.time() * 1000000)}_{request_id}"
        
        # Build payload
        if endpoint_config and endpoint_config.payload_template:
            payload = endpoint_config.payload_template.copy()
            payload.update({
                "request_id": unique_id,
                "timestamp": datetime.now().isoformat()
            })
        else:
            payload = {
                "amount": self.config.amount,
                "transaction_type": "transfer",
                "request_id": unique_id,
                "idempotency_key": unique_id,
                "timestamp": datetime.now().isoformat(),
            }
        
        # Include CSRF in payload
        if self.csrf_token:
            payload["csrf_token"] = self.csrf_token
            payload["_token"] = self.csrf_token
        
        try:
            request_kwargs = {
                "json": payload,
                "headers": headers,
                "timeout": aiohttp.ClientTimeout(total=self.config.timeout)
            }
            
            if proxy:
                request_kwargs["proxy"] = proxy
            
            # Execute request
            if method == "POST":
                async with session.post(url, **request_kwargs) as response:
                    response_time = time.perf_counter() - start_time
                    response_data, transaction_id = await self.parse_response(response)
                    
                    return TestResult(
                        request_id=request_id,
                        status_code=response.status,
                        response_time=response_time,
                        success=response.status in [200, 201, 202],
                        response_data=response_data,
                        timestamp=datetime.now(),
                        csrf_token=self.csrf_token,
                        transaction_id=transaction_id,
                        proxy_used=proxy,
                        endpoint_url=url,
                        retry_count=retry_count
                    )
            
        except asyncio.TimeoutError:
            logger.debug(f"Request {request_id} timed out")
            return TestResult(
                request_id=request_id,
                status_code=0,
                response_time=time.perf_counter() - start_time,
                success=False,
                response_data={"error": "Timeout"},
                timestamp=datetime.now(),
                proxy_used=proxy,
                endpoint_url=url,
                retry_count=retry_count
            )
        except Exception as e:
            logger.debug(f"Request {request_id} failed: {e}")
            return TestResult(
                request_id=request_id,
                status_code=0,
                response_time=time.perf_counter() - start_time,
                success=False,
                response_data={"error": str(e)},
                timestamp=datetime.now(),
                proxy_used=proxy,
                endpoint_url=url,
                retry_count=retry_count
            )
    
    async def parse_response(self, response: aiohttp.ClientResponse) -> Tuple[Dict[Any, Any], Optional[str]]:
        """Parse response and extract transaction ID"""
        try:
            response_data = await response.json()
        except:
            response_data = {"text": await response.text()}
        
        transaction_id = None
        if isinstance(response_data, dict):
            txn_keys = ['transaction_id', 'id', 'txn_id', 'reference', 'transaction_ref', 
                       'order_id', 'payment_id', 'transfer_id']
            for key in txn_keys:
                if key in response_data:
                    transaction_id = str(response_data[key])
                    break
        
        return response_data, transaction_id
    
    async def run_single_race(self, attempt: int = 1) -> List[TestResult]:
        """Execute optimized single race attempt"""
        logger.info(f"{'='*70}")
        logger.info(f"RACE ATTEMPT {attempt}/{self.config.retry_attempts}")
        logger.info(f"{'='*70}")
        
        trigger_event = asyncio.Event()
        
        # Configure connector for maximum performance
        connector_kwargs = {
            "limit": 0,
            "limit_per_host": 0,
            "ttl_dns_cache": 300,
            "enable_cleanup_closed": True,
            "force_close": not self.config.connection_reuse,
        }
        
        connector = aiohttp.TCPConnector(**connector_kwargs)
        
        session_kwargs = {
            "connector": connector,
            "timeout": aiohttp.ClientTimeout(total=self.config.timeout),
        }
        
        # Cookie jar
        if self.session_cookies is None:
            self.session_cookies = aiohttp.CookieJar(unsafe=True)
        session_kwargs["cookie_jar"] = self.session_cookies
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # Warm up
            if attempt == 1:
                await self.warm_up_connection(session)
            
            # Get CSRF token
            if attempt == 1 and not self.csrf_token:
                logger.info("Retrieving CSRF token...")
                self.csrf_token = await self.get_csrf_token(session)
                if self.csrf_token:
                    logger.info(f"CSRF token retrieved: {self.csrf_token[:20]}...")
            
            # Get initial balance
            if self.config.verify_balance and attempt == 1:
                logger.info("Fetching initial balance...")
                self.balance_before = await self.get_balance(session)
                if self.balance_before:
                    logger.info(f"Initial balance: {self.balance_before.balance}")
            
            # Delay before race
            if self.config.delay_before_race > 0:
                logger.info(f"Waiting {self.config.delay_before_race}s before race...")
                await asyncio.sleep(self.config.delay_before_race)
            
            # Create tasks
            logger.info(f"Preparing {self.config.concurrent_requests} concurrent requests...")
            
            if self.config.multi_endpoint and self.config.secondary_endpoints:
                # Multi-endpoint race
                tasks = []
                endpoints = [None] + self.config.secondary_endpoints
                for i in range(self.config.concurrent_requests):
                    endpoint = endpoints[i % len(endpoints)]
                    task = self.send_transaction_with_retry(
                        session, 
                        i + (attempt - 1) * self.config.concurrent_requests,
                        trigger_event,
                        endpoint
                    )
                    tasks.append(task)
            else:
                # Single endpoint race
                tasks = [
                    self.send_transaction_with_retry(
                        session, 
                        i + (attempt - 1) * self.config.concurrent_requests,
                        trigger_event
                    )
                    for i in range(self.config.concurrent_requests)
                ]
            
            await asyncio.sleep(0.05)
            
            logger.info(f"🚀 FIRING {self.config.concurrent_requests} SIMULTANEOUS REQUESTS...")
            start = time.perf_counter()
            
            # Trigger all requests
            trigger_event.set()
            
            # Gather with progress bar
            if TQDM_AVAILABLE:
                results = []
                for coro in tqdm(asyncio.as_completed(tasks), 
                               total=len(tasks), 
                               desc=f"Attempt {attempt}",
                               unit="req"):
                    results.append(await coro)
            else:
                results = await asyncio.gather(*tasks)
            
            elapsed = time.perf_counter() - start
            
            successful = [r for r in results if r.success]
            logger.info(f"Race completed in {elapsed:.4f} seconds")
            logger.info(f"Successful requests: {len(successful)}/{len(results)}")
            
            if len(successful) > 1:
                logger.warning(f"⚠️  MULTIPLE SUCCESSES: {len(successful)} transactions succeeded!")
            
            # Final balance check
            if self.config.verify_balance and attempt == self.config.retry_attempts:
                logger.info("Fetching final balance...")
                await asyncio.sleep(2.0)
                self.balance_after = await self.get_balance(session)
                if self.balance_after:
                    logger.info(f"Final balance: {self.balance_after.balance}")
                    if self.balance_before:
                        change = self.balance_after.balance - self.balance_before.balance
                        expected = self.config.amount
                        if abs(change - expected) > 0.01:
                            logger.error(f"⚠️  UNEXPECTED BALANCE CHANGE!")
                            logger.error(f"   Expected: {expected}, Actual: {change}")
        
        return results
    
    async def run_race_test(self) -> List[TestResult]:
        """Execute comprehensive race condition test"""
        logger.info("="*70)
        logger.info("ADVANCED RACE CONDITION SECURITY TEST v3.0")
        logger.info("="*70)
        logger.info(f"Target: {self.config.target_url}")
        logger.info(f"Concurrent requests: {self.config.concurrent_requests} per attempt")
        logger.info(f"Total attempts: {self.config.retry_attempts}")
        logger.info(f"Amount: {self.config.amount}")
        logger.info(f"Balance verification: {'Enabled' if self.config.verify_balance else 'Disabled'}")
        logger.info(f"Rate limit retry: {'Enabled' if self.config.rate_limit_retry else 'Disabled'}")
        logger.info(f"Distributed testing: {len(self.proxy_pool)} proxies" if len(self.proxy_pool) > 1 else "Single IP")
        if self.config.jitter_ms > 0:
            logger.info(f"Jitter: 0-{self.config.jitter_ms}ms")
        logger.info("="*70)
        
        all_results = []
        
        # Progress bar for attempts
        attempt_iterator = range(1, self.config.retry_attempts + 1)
        if TQDM_AVAILABLE and self.config.retry_attempts > 1:
            attempt_iterator = tqdm(attempt_iterator, desc="Overall Progress", unit="attempt")
        
        for attempt in attempt_iterator:
            results = await self.run_single_race(attempt)
            all_results.extend(results)
            
            successful = [r for r in results if r.success]
            if len(successful) > 1:
                logger.warning(f"VULNERABILITY DETECTED IN ATTEMPT {attempt}!")
                logger.warning(f"{len(successful)} concurrent transactions succeeded")
            
            if attempt < self.config.retry_attempts:
                await asyncio.sleep(0.3)
        
        self.results = all_results
        return all_results
    
    def calculate_confidence(self, multiplier: float, successful_count: int) -> str:
        """Calculate vulnerability confidence level"""
        if multiplier >= 2.0:
            return "CRITICAL"
        elif multiplier >= 1.5:
            return "HIGH"
        elif successful_count > 5:
            return "HIGH"
        elif successful_count > 2:
            return "MEDIUM"
        elif successful_count > 1:
            return "LOW"
        return "NONE"
    
    def analyze_results(self) -> Dict[str, Any]:
        """Comprehensive vulnerability analysis"""
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        # Per-attempt analysis
        attempts_data = {}
        for i in range(self.config.retry_attempts):
            start_idx = i * self.config.concurrent_requests
            end_idx = (i + 1) * self.config.concurrent_requests
            attempt_results = self.results[start_idx:end_idx]
            attempt_successful = [r for r in attempt_results if r.success]
            attempts_data[f"attempt_{i+1}"] = {
                "total": len(attempt_results),
                "successful": len(attempt_successful),
                "failed": len(attempt_results) - len(attempt_successful),
                "vulnerability_found": len(attempt_successful) > 1,
                "avg_response_time": sum(r.response_time for r in attempt_results) / len(attempt_results) if attempt_results else 0
            }
        
        analysis = {
            "test_timestamp": datetime.now().isoformat(),
            "total_requests": len(self.results),
            "total_attempts": self.config.retry_attempts,
            "successful_requests": len(successful),
            "failed_requests": len(failed),
            "success_rate": len(successful) / len(self.results) * 100 if self.results else 0,
            "avg_response_time": sum(r.response_time for r in self.results) / len(self.results) if self.results else 0,
            "min_response_time": min(r.response_time for r in self.results) if self.results else 0,
            "max_response_time": max(r.response_time for r in self.results) if self.results else 0,
            "attempts_breakdown": attempts_data,
            "rate_limit_detected": self.rate_limit_detected
        }
        
        # Transaction ID analysis
        transaction_ids = [r.transaction_id for r in successful if r.transaction_id]
        unique_txn_ids = set(transaction_ids)
        analysis["unique_transaction_ids"] = len(unique_txn_ids)
        analysis["total_transaction_ids"] = len(transaction_ids)
        analysis["duplicate_transactions"] = len(transaction_ids) - len(unique_txn_ids)
        
        # Status codes
        status_codes = {}
        for result in self.results:
            status_codes[result.status_code] = status_codes.get(result.status_code, 0) + 1
        analysis["status_code_distribution"] = status_codes
        
        # Proxy distribution
        if len(self.proxy_pool) > 1:
            proxy_stats = {}
            for result in successful:
                proxy = result.proxy_used or "none"
                proxy_stats[proxy] = proxy_stats.get(proxy, 0) + 1
            analysis["proxy_distribution"] = proxy_stats
        
        # Balance verification - MOST IMPORTANT
        if self.balance_before and self.balance_after:
            balance_change = self.balance_after.balance - self.balance_before.balance
            expected_change = self.config.amount
            multiplier = balance_change / expected_change if expected_change > 0 else 0
            
            analysis["balance_verification"] = {
                "before": self.balance_before.balance,
                "after": self.balance_after.balance,
                "change": balance_change,
                "expected_change": expected_change,
                "multiplier": multiplier,
                "unexpected_change": abs(balance_change - expected_change) > 0.01
            }
            
            # Determine vulnerability
            if balance_change > expected_change + 0.01:
                times_processed = round(multiplier)
                confidence = self.calculate_confidence(multiplier, times_processed)
                
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = confidence
                analysis["vulnerability_confidence"] = "CONFIRMED"
                analysis["details"] = f"Balance changed by {balance_change} ({multiplier:.2f}x expected). ~{times_processed} transactions processed!"
                analysis["exploitation_count"] = times_processed
            elif len(successful) > 1:
                confidence = self.calculate_confidence(1.0, len(successful))
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = confidence
                analysis["vulnerability_confidence"] = "PROBABLE"
                analysis["details"] = f"{len(successful)} requests succeeded (HTTP 200/201) but balance verification inconclusive"
                analysis["exploitation_count"] = len(successful)
            else:
                analysis["race_condition_detected"] = False
                analysis["vulnerability_severity"] = "NONE"
                analysis["vulnerability_confidence"] = "CONFIRMED"
                analysis["details"] = "System properly handled concurrent requests. No race condition detected."
        else:
            # No balance verification
            if len(successful) > 1:
                confidence = self.calculate_confidence(1.0, len(successful))
                analysis["race_condition_detected"] = True
                analysis["vulnerability_severity"] = confidence
                analysis["vulnerability_confidence"] = "UNCONFIRMED"
                analysis["details"] = f"{len(successful)} requests succeeded. Balance verification strongly recommended."
                analysis["exploitation_count"] = len(successful)
            else:
                analysis["race_condition_detected"] = False
                analysis["vulnerability_severity"] = "NONE"
                analysis["vulnerability_confidence"] = "LOW"
                analysis["details"] = "No obvious vulnerability. Use --verify-balance for confirmation."
        
        return analysis
    
    def print_report(self, analysis: Dict[str, Any]):
        """Generate professional vulnerability report"""
        logger.info("\n" + "="*70)
        logger.info("RACE CONDITION VULNERABILITY ASSESSMENT REPORT")
        logger.info("="*70)
        logger.info(f"Test Date: {analysis['test_timestamp']}")
        logger.info(f"Target: {self.config.target_url}")
        
        logger.info("\n" + "-"*70)
        logger.info("TEST STATISTICS")
        logger.info("-"*70)
        logger.info(f"Total Requests: {analysis['total_requests']}")
        logger.info(f"Successful: {analysis['successful_requests']}")
        logger.info(f"Failed: {analysis['failed_requests']}")
        logger.info(f"Success Rate: {analysis['success_rate']:.2f}%")
        logger.info(f"Avg Response Time: {analysis['avg_response_time']:.4f}s")
        
        if analysis.get('rate_limit_detected'):
            logger.warning("⚠️  Rate limiting detected during testing")
        
        logger.info("\nHTTP Status Distribution:")
        for code, count in sorted(analysis['status_code_distribution'].items()):
            pct = (count / analysis['total_requests']) * 100
            logger.info(f"  {code}: {count} ({pct:.1f}%)")
        
        # Per-attempt breakdown
        logger.info("\n" + "-"*70)
        logger.info("PER-ATTEMPT ANALYSIS")
        logger.info("-"*70)
        for key, data in analysis['attempts_breakdown'].items():
            vuln = "🚨 VULNERABLE" if data['vulnerability_found'] else "✓ Secure"
            logger.info(f"{key}: {data['successful']}/{data['total']} succeeded ({data['avg_response_time']:.4f}s avg) - {vuln}")
        
        # Balance verification
        if 'balance_verification' in analysis:
            bv = analysis['balance_verification']
            logger.info("\n" + "-"*70)
            logger.info("BALANCE VERIFICATION (CRITICAL)")
            logger.info("-"*70)
            logger.info(f"Before: {bv['before']}")
            logger.info(f"After: {bv['after']}")
            logger.info(f"Change: {bv['change']}")
            logger.info(f"Expected: {bv['expected_change']}")
            logger.info(f"Multiplier: {bv['multiplier']:.2f}x")
            
            if bv['unexpected_change']:
                logger.critical("🚨 CRITICAL: UNEXPECTED BALANCE CHANGE!")
                logger.critical(f"   Balance multiplied by {bv['multiplier']:.2f}x!")
        
        # Vulnerability verdict
        logger.info("\n" + "="*70)
        logger.info("VULNERABILITY VERDICT")
        logger.info("="*70)
        
        if analysis['race_condition_detected']:
            logger.critical("Status: 🚨 VULNERABLE")
            logger.critical(f"Severity: {analysis['vulnerability_severity']}")
            logger.critical(f"Confidence: {analysis['vulnerability_confidence']}")
            logger.critical(f"\n{analysis['details']}")
            
            if 'exploitation_count' in analysis:
                impact = analysis['exploitation_count'] * self.config.amount
                logger.critical(f"\nExploitation Impact:")
                logger.critical(f"  Transactions Exploited: {analysis['exploitation_count']}")
                logger.critical(f"  Financial Impact: {impact}")
            
            logger.info(f"\n🛡️  REMEDIATION RECOMMENDATIONS:")
            logger.info("  1. Implement pessimistic locking (SELECT FOR UPDATE)")
            logger.info("  2. Use distributed locks (Redis SETNX with TTL)")
            logger.info("  3. Enforce strict idempotency key validation")
            logger.info("  4. Add request deduplication layer")
            logger.info("  5. Implement optimistic locking with version control")
            logger.info("  6. Add rate limiting per user/session")
            logger.info("  7. Use database transactions with SERIALIZABLE isolation")
        else:
            logger.info("Status: ✓ NOT VULNERABLE")
            logger.info(f"Severity: {analysis['vulnerability_severity']}")
            logger.info(f"Confidence: {analysis['vulnerability_confidence']}")
            logger.info(f"\n{analysis['details']}")
            
            if analysis['vulnerability_confidence'] != "CONFIRMED":
                logger.warning("\n⚠️  Recommendation: Enable --verify-balance for higher confidence")
        
        logger.info("="*70 + "\n")
    
    def save_results(self, analysis: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Save comprehensive results"""
        if filename is None:
            status = "VULNERABLE" if analysis['race_condition_detected'] else "SECURE"
            severity = analysis.get('vulnerability_severity', 'NONE')
            filename = f"race_test_{status}_{severity}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output = {
            "metadata": {
                "tool": "Advanced Race Condition Tester v3.0 Enterprise",
                "test_date": analysis['test_timestamp'],
                "tester": "Security Assessment Team",
                "tool_version": "3.0.0"
            },
            "config": {k: v for k, v in asdict(self.config).items() if k not in ['auth_token', 'proxy_list']},
            "analysis": analysis,
            "detailed_results": [
                {
                    "request_id": r.request_id,
                    "status_code": r.status_code,
                    "response_time": round(r.response_time, 4),
                    "success": r.success,
                    "timestamp": r.timestamp.isoformat(),
                    "transaction_id": r.transaction_id,
                    "proxy_used": r.proxy_used,
                    "endpoint_url": r.endpoint_url,
                    "retry_count": r.retry_count
                }
                for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info(f"[+] Detailed results saved to: {filename}")
        return filename

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Advanced Race Condition Tester v3.0 - Enterprise Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic vulnerability test
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN -c 100
  
  # Comprehensive test with balance verification (RECOMMENDED)
  %(prog)s -u https://api.example.com/transaction \\
           -b https://api.example.com/balance \\
           -t YOUR_TOKEN --verify-balance -c 100 --retry 10
  
  # Distributed testing with multiple proxies
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN \\
           --proxy-list proxies.txt -c 150 --retry 20
  
  # Multi-endpoint race (deposit + withdraw)
  %(prog)s -u https://api.example.com/deposit -t YOUR_TOKEN \\
           --multi-endpoint --secondary https://api.example.com/withdraw \\
           -c 100 --retry 10
  
  # Maximum intensity test
  %(prog)s -u https://api.example.com/transaction -t YOUR_TOKEN \\
           -b https://api.example.com/balance --verify-balance \\
           -c 200 --retry 30 --warm-up --rate-limit-retry \\
           --proxy http://127.0.0.1:8080 -v
        """
    )
    
    # Basic options
    parser.add_argument('-u', '--url', required=True, help='Target transaction URL')
    parser.add_argument('-b', '--balance-url', help='Balance check URL (HIGHLY RECOMMENDED)')
    parser.add_argument('-t', '--token', required=True, help='Authentication token')
    parser.add_argument('-a', '--amount', type=float, default=100.0, help='Transaction amount (default: 100.0)')
    
    # Concurrency options
    parser.add_argument('-c', '--concurrent', type=int, default=50, 
                       help='Concurrent requests per attempt (default: 50, recommended: 100+)')
    parser.add_argument('--retry', type=int, default=1, 
                       help='Number of race attempts (default: 1, recommended: 10-30)')
    parser.add_argument('--jitter', type=int, default=0, 
                       help='Random jitter in milliseconds (default: 0)')
    parser.add_argument('--delay', type=float, default=0.0, 
                       help='Delay before each race in seconds')
    
    # Network options
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--proxy', help='Single proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxy-list', type=str, 
                       help='File with proxy list (one per line) for distributed testing')
    
    # Feature toggles
    parser.add_argument('--verify-balance', action='store_true', 
                       help='Verify balance before/after (HIGHLY RECOMMENDED)')
    parser.add_argument('--warm-up', action='store_true', 
                       help='Warm up connections before testing (recommended)')
    parser.add_argument('--no-warm-up', action='store_true', 
                       help='Disable connection warm-up')
    parser.add_argument('--rate-limit-retry', action='store_true', default=True,
                       help='Automatically retry on rate limits (default: enabled)')
    parser.add_argument('--no-rate-limit-retry', action='store_true',
                       help='Disable automatic rate limit retry')
    parser.add_argument('--rate-limit-backoff', type=float, default=1.0,
                       help='Initial backoff delay for rate limits (default: 1.0s)')
    parser.add_argument('--no-connection-reuse', action='store_true',
                       help='Disable HTTP connection reuse')
    
    # Multi-endpoint options
    parser.add_argument('--multi-endpoint', action='store_true',
                       help='Enable multi-endpoint race testing')
    parser.add_argument('--secondary', action='append', dest='secondary_urls',
                       help='Secondary endpoint URL (can be used multiple times)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output filename for JSON results')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose logging (DEBUG level)')
    parser.add_argument('--log-file', help='Custom log file path')
    
    return parser.parse_args()

async def main():
    """Main execution function"""
    args = parse_args()
    
    # Setup logging
    log_file = setup_logging(args.log_file, args.verbose)
    logger.info(f"Logging to: {log_file}")
    
    # Load proxy list if provided
    proxy_list = None
    if args.proxy_list:
        try:
            with open(args.proxy_list, 'r') as f:
                proxy_list = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(proxy_list)} proxies from {args.proxy_list}")
        except Exception as e:
            logger.error(f"Failed to load proxy list: {e}")
            sys.exit(1)
    
    # Parse secondary endpoints for multi-endpoint testing
    secondary_endpoints = []
    if args.multi_endpoint and args.secondary_urls:
        for url in args.secondary_urls:
            secondary_endpoints.append(EndpointConfig(url=url, method="POST"))
        logger.info(f"Multi-endpoint mode: {len(secondary_endpoints)} secondary endpoints")
    
    # Handle conflicting options
    warm_up = args.warm_up and not args.no_warm_up
    rate_limit_retry = args.rate_limit_retry and not args.no_rate_limit_retry
    connection_reuse = not args.no_connection_reuse
    
    # Warnings for suboptimal configuration
    if not args.verify_balance:
        logger.warning("⚠️  Balance verification disabled. Results may be inconclusive.")
        logger.warning("   Recommendation: Use --verify-balance -b <balance_url>")
    
    if args.concurrent < 50:
        logger.warning(f"⚠️  Low concurrency ({args.concurrent}). May not trigger race condition.")
        logger.warning("   Recommendation: Use -c 100 or higher")
    
    if args.retry < 5:
        logger.warning(f"⚠️  Few retry attempts ({args.retry}). Consider using more.")
        logger.warning("   Recommendation: Use --retry 10-30 for thorough testing")
    
    # Create configuration
    config = TestConfig(
        target_url=args.url,
        balance_url=args.balance_url,
        auth_token=args.token,
        amount=args.amount,
        concurrent_requests=args.concurrent,
        timeout=args.timeout,
        proxy=args.proxy,
        proxy_list=proxy_list,
        retry_attempts=args.retry,
        jitter_ms=args.jitter,
        verify_balance=args.verify_balance,
        delay_before_race=args.delay,
        warm_up=warm_up,
        rate_limit_retry=rate_limit_retry,
        rate_limit_backoff=args.rate_limit_backoff,
        connection_reuse=connection_reuse,
        multi_endpoint=args.multi_endpoint,
        secondary_endpoints=secondary_endpoints
    )
    
    logger.info("\n" + "="*70)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("="*70)
    logger.info(f"Target URL: {config.target_url}")
    logger.info(f"Balance URL: {config.balance_url or 'Not configured'}")
    logger.info(f"Amount per transaction: {config.amount}")
    logger.info(f"Concurrent requests: {config.concurrent_requests}")
    logger.info(f"Total attempts: {config.retry_attempts}")
    logger.info(f"Total requests: {config.concurrent_requests * config.retry_attempts}")
    logger.info(f"Warm-up: {'Enabled' if config.warm_up else 'Disabled'}")
    logger.info(f"Rate limit retry: {'Enabled' if config.rate_limit_retry else 'Disabled'}")
    logger.info(f"Connection reuse: {'Enabled' if config.connection_reuse else 'Disabled'}")
    logger.info(f"Multi-endpoint: {'Enabled' if config.multi_endpoint else 'Disabled'}")
    if proxy_list:
        logger.info(f"Distributed testing: {len(proxy_list)} proxies")
    elif args.proxy:
        logger.info(f"Proxy: {args.proxy}")
    logger.info("="*70 + "\n")
    
    # Create and run tester
    tester = RaceConditionTester(config)
    
    try:
        logger.info("Starting race condition test...")
        results = await tester.run_race_test()
        
        logger.info("\nAnalyzing results...")
        analysis = tester.analyze_results()
        
        tester.print_report(analysis)
        
        output_file = tester.save_results(analysis, args.output)
        
        logger.info(f"\n{'='*70}")
        logger.info("TEST COMPLETE")
        logger.info(f"{'='*70}")
        logger.info(f"Results saved to: {output_file}")
        logger.info(f"Log file: {log_file}")
        
        # Exit code based on vulnerability
        if analysis['race_condition_detected']:
            logger.critical("\n🚨 VULNERABILITY DETECTED - Review results immediately!")
            sys.exit(1)
        else:
            logger.info("\n✓ No vulnerability detected")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("\n[!] Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"\n[!] Fatal error: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)