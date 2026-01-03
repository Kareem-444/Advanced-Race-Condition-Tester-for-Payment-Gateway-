# Advanced Race Condition Tester for Payment Gateways

## Overview

This tool is designed for authorized security testing of payment gateways and financial APIs to identify race condition vulnerabilities. Race conditions occur when multiple simultaneous requests can bypass proper transaction validation, potentially allowing duplicate payments, balance manipulation, or other unintended behaviors.

**⚠️ AUTHORIZED USE ONLY**: This tool should only be used in controlled testing environments with explicit written permission. Unauthorized testing against production systems may violate laws and terms of service.

## What are Race Conditions?

A race condition vulnerability in payment systems occurs when:
1. Multiple requests are processed simultaneously
2. The system fails to properly lock or validate resources
3. Multiple transactions succeed when only one should

**Example**: If you send 100 simultaneous $100 withdrawal requests, a vulnerable system might process multiple requests instead of just one, resulting in unauthorized fund transfers.

## How This Tool Works

### Core Architecture

The tool uses Python's `asyncio` and `aiohttp` libraries to send highly concurrent HTTP requests with precise timing control. Here's the workflow:

1. **Initialization**: Establishes a connection pool and shared session
2. **CSRF Token Retrieval**: Automatically fetches CSRF tokens if required by the API
3. **Balance Check (Pre-Race)**: Records the account balance before testing
4. **Synchronization**: Creates multiple coroutines that wait for a trigger event
5. **Simultaneous Execution**: All requests fire at exactly the same moment
6. **Balance Check (Post-Race)**: Verifies the final balance
7. **Analysis**: Compares expected vs actual results to detect vulnerabilities

### Key Components

#### 1. **Session Management**
```python
self.session_cookies = aiohttp.CookieJar()
```
Maintains cookies across all requests to simulate a real user session. This is critical because many payment APIs use session-based authentication.

#### 2. **CSRF Token Handling**
```python
async def get_csrf_token(self, session):
```
Before the race begins, the tool makes an initial request to retrieve any CSRF tokens. These tokens are then included in all subsequent requests, mimicking legitimate client behavior.

#### 3. **Trigger Event Synchronization**
```python
trigger_event = asyncio.Event()
await trigger_event.wait()  # All coroutines wait here
trigger_event.set()  # All fire simultaneously
```
This is the heart of the race condition test. All coroutines are created and wait at the same point, then are released simultaneously to create maximum concurrency pressure.

#### 4. **Balance Verification**
```python
balance_change = self.balance_after.balance - self.balance_before.balance
expected_change = self.config.amount
```
The most reliable detection method. Instead of relying on HTTP status codes, the tool checks if the actual balance change exceeds what should be possible with a single transaction.

#### 5. **Connection Pooling**
```python
connector = aiohttp.TCPConnector(
    limit=concurrent_requests,
    limit_per_host=concurrent_requests
)
```
Removes connection limits to ensure all requests can be sent simultaneously without being queued by the HTTP client.

## Installation

### Requirements
- Python 3.7+
- aiohttp library

### Setup
```bash
# Install dependencies
pip install aiohttp

# Download the script
wget https://your-repo/race_condition_tester.py
# or
curl -O https://your-repo/race_condition_tester.py

# Make it executable (optional)
chmod +x race_condition_tester.py
```

## Usage

### Basic Command Structure
```bash
python race_condition_tester.py -u <TARGET_URL> -t <AUTH_TOKEN> [OPTIONS]
```

### Common Use Cases

#### 1. Basic Race Condition Test
Test with 50 concurrent requests:
```bash
python race_condition_tester.py \
  -u https://api.example.com/transaction \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 2. Balance Verification Test (Recommended)
Most reliable method - verifies actual financial impact:
```bash
python race_condition_tester.py \
  -u https://api.example.com/transaction \
  -b https://api.example.com/balance \
  -t YOUR_AUTH_TOKEN \
  --verify-balance
```

#### 3. High-Intensity Test with Retries
Applies continuous pressure with multiple race attempts:
```bash
python race_condition_tester.py \
  -u https://api.example.com/transaction \
  -t YOUR_AUTH_TOKEN \
  -c 100 \
  --retry 20
```

#### 4. Testing Through Burp Suite
Route all traffic through Burp Suite for detailed analysis:
```bash
python race_condition_tester.py \
  -u https://api.example.com/transaction \
  -t YOUR_AUTH_TOKEN \
  --proxy http://127.0.0.1:8080
```

#### 5. Advanced Test with All Features
```bash
python race_condition_tester.py \
  -u https://api.example.com/transaction \
  -b https://api.example.com/balance \
  -t YOUR_AUTH_TOKEN \
  -a 100.0 \
  -c 100 \
  --retry 10 \
  --jitter 50 \
  --verify-balance \
  --proxy http://127.0.0.1:8080 \
  -o results.json
```

## Command Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--url` | `-u` | Yes | Target transaction endpoint URL |
| `--token` | `-t` | Yes | Authentication token (JWT, Bearer, etc.) |
| `--balance-url` | `-b` | No | Balance check endpoint for verification |
| `--amount` | `-a` | No | Transaction amount (default: 100.0) |
| `--concurrent` | `-c` | No | Concurrent requests per attempt (default: 50) |
| `--timeout` | | No | Request timeout in seconds (default: 10) |
| `--proxy` | | No | Proxy URL (e.g., http://127.0.0.1:8080) |
| `--retry` | | No | Number of race attempts (default: 1) |
| `--jitter` | | No | Random delay 0-N milliseconds (default: 0) |
| `--verify-balance` | | No | Enable balance verification |
| `--output` | `-o` | No | Output filename for JSON results |

## Understanding the Output

### Terminal Output

```
[*] Starting race condition test at 2026-01-03 14:30:25
[*] Target: https://api.example.com/transaction
[*] Concurrent requests per attempt: 50
[*] Total attempts: 1
[*] Amount per request: 100.0
[*] Using proxy: http://127.0.0.1:8080
[*] Retrieving CSRF token...
[+] CSRF token retrieved: a3f2c8e9b1d4a7e6...
[*] Fetching balance before race...
[+] Balance before: 1000.0

[*] Race attempt 1/1
[*] Triggering 50 simultaneous requests...
[*] Race completed in 0.234 seconds
[*] Fetching balance after race...
[+] Balance after: 1100.0

======================================================================
RACE CONDITION TEST REPORT
======================================================================
Total Requests: 50
Successful: 1
Failed: 49
Success Rate: 2.00%

Response Times:
  Average: 0.145s
  Min: 0.089s
  Max: 0.234s

Status Code Distribution:
  200: 1
  409: 49

Balance Verification:
  Before: 1000.0
  After: 1100.0
  Change: 100.0 (expected: 100.0)

======================================================================
Race Condition Detected: False
Vulnerability Severity: NONE
======================================================================
```

### Vulnerability Detection

The tool detects race conditions through multiple indicators:

#### 1. **Balance Anomaly (CRITICAL)**
```
Balance Verification:
  Before: 1000.0
  After: 1300.0
  Change: 300.0 (expected: 100.0)
  ⚠️  UNEXPECTED BALANCE CHANGE DETECTED!

Race Condition Detected: True
Vulnerability Severity: CRITICAL
Details: Balance increased by 300.0 (expected 100.0). Multiple transactions processed!
```
This indicates 3 transactions succeeded when only 1 should have.

#### 2. **Multiple Successful Requests (HIGH)**
```
Successful Requests: 5
Race Condition Detected: True
Vulnerability Severity: HIGH
Details: Multiple concurrent transactions succeeded: 5
```

#### 3. **No Vulnerability Detected (NONE)**
```
Successful Requests: 1
Failed Requests: 49
Race Condition Detected: False
Vulnerability Severity: NONE
```
The system properly handled concurrent requests.

### JSON Output

Results are saved to a JSON file with complete details:

```json
{
  "config": {
    "target_url": "https://api.example.com/transaction",
    "amount": 100.0,
    "concurrent_requests": 50,
    "retry_attempts": 1
  },
  "analysis": {
    "total_requests": 50,
    "successful_requests": 1,
    "race_condition_detected": false,
    "vulnerability_severity": "NONE",
    "balance_verification": {
      "before": 1000.0,
      "after": 1100.0,
      "change": 100.0,
      "expected_change": 100.0
    }
  },
  "results": [
    {
      "request_id": 0,
      "status_code": 200,
      "response_time": 0.145,
      "success": true,
      "timestamp": "2026-01-03T14:30:25.123456"
    }
  ]
}
```

## Testing Strategies

### 1. **Incremental Approach**
Start with low concurrency and increase gradually:
```bash
# Test 1: 10 concurrent requests
python race_condition_tester.py -u URL -t TOKEN -c 10

# Test 2: 50 concurrent requests
python race_condition_tester.py -u URL -t TOKEN -c 50

# Test 3: 100 concurrent requests
python race_condition_tester.py -u URL -t TOKEN -c 100
```

### 2. **Sustained Pressure**
Some race conditions only appear under sustained load:
```bash
python race_condition_tester.py -u URL -t TOKEN -c 50 --retry 20
```

### 3. **Timing Variations**
Add jitter to test different timing windows:
```bash
# Test with 0-100ms random delays
python race_condition_tester.py -u URL -t TOKEN --jitter 100
```

### 4. **Different Transaction Types**
Test various endpoints:
- Withdrawals: `/api/withdraw`
- Deposits: `/api/deposit`
- Transfers: `/api/transfer`
- Purchases: `/api/purchase`

## Integration with Burp Suite

### Setup
1. Start Burp Suite and configure proxy (default: `127.0.0.1:8080`)
2. Run the tool with `--proxy` flag
3. All requests appear in Burp's HTTP history
4. Use Burp's Repeater/Intruder for additional analysis

### Benefits
- Visual inspection of all requests/responses
- Manual manipulation of specific requests
- SSL/TLS interception for HTTPS endpoints
- Extension integration (Logger++, etc.)

## Best Practices

### Security Testing Guidelines

1. **Always Get Written Permission**
   - Document the scope of testing
   - Define allowed test accounts
   - Set testing time windows
   - Establish communication protocols

2. **Use Test Environments**
   - Never test production systems first
   - Use dedicated test accounts with fake money
   - Ensure rollback procedures are in place

3. **Monitor System Impact**
   - Watch for service degradation
   - Monitor error rates
   - Check system logs
   - Be ready to stop testing immediately

4. **Document Everything**
   - Save all test results
   - Screenshot vulnerability findings
   - Record steps to reproduce
   - Note timestamp of discovery

### Remediation Recommendations

If you discover a race condition vulnerability, recommend these fixes:

1. **Database-Level Locking**
   ```sql
   SELECT * FROM accounts WHERE id = ? FOR UPDATE
   ```

2. **Distributed Locks (Redis)**
   ```python
   with redis_lock(f"transaction:{user_id}"):
       process_transaction()
   ```

3. **Idempotency Keys**
   ```python
   if check_idempotency_key(request.idempotency_key):
       return cached_response
   ```

4. **Optimistic Locking**
   ```python
   UPDATE accounts SET balance = balance - 100, version = version + 1
   WHERE id = ? AND version = ?
   ```

## Troubleshooting

### Common Issues

#### 1. All Requests Fail with Timeout
**Problem**: Network/firewall blocking
**Solution**: 
- Check proxy settings
- Verify target URL is accessible
- Increase `--timeout` value
- Check firewall rules

#### 2. CSRF Token Errors
**Problem**: Token expired or not found
**Solution**:
- Verify the token endpoint is correct
- Check if manual token passing is needed
- Review API documentation for token requirements

#### 3. "Connection pool is full"
**Problem**: Too many concurrent connections
**Solution**:
- Reduce `-c` value
- Increase system file descriptor limit: `ulimit -n 4096`

#### 4. Balance URL Returns 403/401
**Problem**: Insufficient permissions
**Solution**:
- Verify token has balance read permissions
- Check if separate endpoint authentication is needed
- Use the same token that works for transactions

## Security Considerations

### Responsible Disclosure

If you find a vulnerability:

1. **Do Not Exploit**: Stop testing immediately upon discovery
2. **Document**: Save all evidence securely
3. **Report**: Contact the organization's security team
4. **Wait**: Allow reasonable time for fix (typically 90 days)
5. **Verify**: Confirm the fix resolves the issue

### Legal Compliance

- Ensure you have a signed authorization letter
- Comply with applicable laws (CFAA, Computer Misuse Act, etc.)
- Follow responsible disclosure guidelines
- Maintain confidentiality of findings

## Advanced Techniques

### Custom Request Payloads

Modify the `send_transaction()` method to test specific scenarios:

```python
payload = {
    "amount": self.config.amount,
    "recipient": "test_account",
    "currency": "USD",
    "memo": f"Race test {request_id}"
}
```

### Rate Limiting Bypass Testing

Test if rate limits properly prevent races:

```bash
# Quick succession of races
for i in {1..10}; do
    python race_condition_tester.py -u URL -t TOKEN -c 50
    sleep 1
done
```

### Time-of-Check vs Time-of-Use (TOCTOU)

Add delays between balance check and transaction to exploit TOCTOU:

```python
# Check balance
balance = get_balance()
# Artificial delay
await asyncio.sleep(0.1)
# Process transaction (balance may have changed)
process_transaction()
```

## Contributing

Improvements and contributions are welcome. Areas for enhancement:

- Support for authentication methods beyond Bearer tokens
- WebSocket support for real-time APIs
- GraphQL query support
- Multi-stage transaction testing
- Automated report generation

## License

This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before use.

## Disclaimer

This tool is intended solely for authorized security testing and research. The authors assume no liability for misuse or damage caused by this tool. Always obtain explicit written permission before testing any system you do not own.
