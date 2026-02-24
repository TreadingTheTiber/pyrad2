# RFC 9765 (RADIUS/1.1 with ALPN) — Implementation Evaluation for pyrad2

## RFC Summary

[RFC 9765](https://datatracker.ietf.org/doc/rfc9765/) (April 2025, Experimental) defines
RADIUS/1.1, a transport profile for RADIUS over (D)TLS that eliminates MD5 from the
application layer by relying entirely on TLS 1.3+ for security. It uses TLS
Application-Layer Protocol Negotiation (ALPN) to negotiate between the legacy RADIUS/TLS
profile (`radius/1.0`) and the new profile (`radius/1.1`).

### Key changes in RADIUS/1.1 vs legacy RADIUS/TLS

| Aspect | Legacy RADIUS/TLS (1.0) | RADIUS/1.1 |
|---|---|---|
| Packet ID field | 8-bit Identifier (0-255) | Reserved-1 (set to zero) |
| Authenticator field | 16-byte Request/Response Authenticator | 4-byte Token + 12-byte Reserved-2 |
| Request/Response matching | By Identifier + MD5 hash | By Token (4-byte, counter-based) |
| User-Password | MD5-obfuscated (RFC 2865 §5.2) | Plaintext string (TLS protects it) |
| Tunnel-Password | MD5-obfuscated with salt (RFC 2868 §3.5) | Plain string, no salt |
| MS-MPPE keys | MD5-obfuscated | Plain string |
| Message-Authenticator | HMAC-MD5, often required | Prohibited (silently discarded) |
| Shared secret usage | Used for MD5 operations | Not used at application layer |
| TLS version | TLS 1.2+ | TLS 1.3+ required |

---

## Current pyrad2 Architecture

### Relevant modules

| Module | Purpose | RADIUS/1.1 impact |
|---|---|---|
| `pyrad2/packet.py` | Packet encode/decode, MD5 authenticators, password obfuscation | **Heavy** — core packet format changes |
| `pyrad2/radsec/client.py` | RadSec (TLS) client, `asyncio.open_connection` with SSL | **Medium** — ALPN negotiation, Token tracking |
| `pyrad2/radsec/server.py` | RadSec (TLS) server, `asyncio.start_server` with SSL | **Medium** — ALPN negotiation, Token tracking |
| `pyrad2/tools.py` | Attribute encode/decode, `read_radius_packet()` | **Low** — stream reader unchanged |
| `pyrad2/client.py` | UDP RADIUS client | **None** — RFC 9765 only applies to (D)TLS |
| `pyrad2/server.py` | UDP RADIUS server, `RemoteHost` dataclass | **Low** — no packet changes needed |
| `pyrad2/server_async.py` | Async UDP RADIUS server | **None** — UDP transport unchanged |
| `pyrad2/host.py` | Base host class, packet factory methods | **Low** — factory methods may need mode param |
| `pyrad2/proxy.py` | RADIUS proxy (UDP) | **None** — UDP transport unchanged |
| `pyrad2/constants.py` | Packet type codes, data types | **Low** — may add Protocol-Error code |

### Current MD5 usage in pyrad2 (all in `packet.py`)

1. **`AuthPacket.PwCrypt()` / `PwDecrypt()`** — MD5-based password obfuscation (RFC 2865 §5.2)
2. **`Packet.SaltCrypt()` / `SaltDecrypt()`** — Salt-based MD5 obfuscation (Tunnel-Password, RFC 2868)
3. **`Packet.ReplyPacket()`** — MD5-based Response Authenticator generation
4. **`Packet.VerifyReply()`** — MD5-based Response Authenticator verification
5. **`Packet.VerifyPacket()`** — MD5-based Request Authenticator verification
6. **`Packet._refresh_message_authenticator()`** — HMAC-MD5 Message-Authenticator
7. **`Packet.verify_message_authenticator()`** — HMAC-MD5 verification
8. **`AcctPacket.RequestPacket()`** — MD5 Authenticator for accounting requests
9. **`CoAPacket.RequestPacket()`** — MD5 Authenticator for CoA requests

---

## Implementation Work Items

### 1. ALPN Negotiation in TLS Setup — Moderate

**What:** Add ALPN protocol string configuration and negotiation to both `RadSecClient`
and `RadSecServer`.

**Details:**
- Python's `ssl.SSLContext.set_alpn_protocols()` is available and supports this directly
- Add a `version` configuration parameter accepting `"1.0"`, `"1.1"`, or `"1.0,1.1"` (default)
- Map to ALPN protocol strings: `["radius/1.0"]`, `["radius/1.1"]`, or both
- After TLS handshake, check `ssl_object.selected_alpn_protocol()` to determine negotiated version
- Store the negotiated version as connection-level state
- Handle version mismatch: close connection with appropriate error

**Files affected:**
- `pyrad2/radsec/client.py` — `RadSecClient.__init__()`, `setup_ssl()`, `_send_packet()`
- `pyrad2/radsec/server.py` — `RadSecServer.__init__()`, `setup_ssl()`, `_handle_client()`

**Complexity:** Moderate. Python's `ssl` module supports ALPN natively. The main challenge is
plumbing the negotiated version through to the packet encode/decode layer.

### 2. Packet Header Format Changes — Large

**What:** Support the RADIUS/1.1 header format where the Identifier becomes Reserved-1
(zero) and the 16-byte Authenticator becomes a 4-byte Token + 12-byte Reserved-2.

**Current header structure (20 bytes):**
```
Code(1) | ID(1) | Length(2) | Authenticator(16)
```

**RADIUS/1.1 header structure (20 bytes):**
```
Code(1) | Reserved-1(1, zero) | Length(2) | Token(4) | Reserved-2(12, zero)
```

**Details:**
- `Packet.DecodePacket()` currently unpacks `!BBH16s` — needs a mode-aware path that
  extracts Token from bytes 4-8 and ignores bytes 8-20
- `AuthPacket.RequestPacket()`, `AcctPacket.RequestPacket()`, `CoAPacket.RequestPacket()`,
  `Packet.ReplyPacket()` — all build headers with `struct.pack("!BBH16s", ...)` and need
  an alternate path for RADIUS/1.1
- `Packet.CreateReply()` must copy the Token (not the authenticator) for response matching
- `Packet.VerifyReply()` must match by Token instead of ID + MD5 hash

**Token management:**
- Initialize a random 32-bit counter when a connection opens
- Increment for each new packet sent on that connection
- Token is per-connection state, not per-packet — this requires a new abstraction since
  pyrad2 currently treats packets as independent objects

**Files affected:**
- `pyrad2/packet.py` — `Packet`, `AuthPacket`, `AcctPacket`, `CoAPacket` (all packet classes)

**Complexity:** Large. This is the most invasive change. The packet classes currently have no
concept of "connection" or "transport mode" — they encode/decode independently. RADIUS/1.1
requires packets to know their mode, and Token management requires per-connection state.

**Design consideration:** The cleanest approach is likely a `protocol_version` attribute on each
packet instance (set at construction time based on the negotiated ALPN), with conditional
encode/decode paths. Token counter state should live on the connection (client/server), not
on individual packets.

### 3. Attribute Encoding Changes — Large

**What:** In RADIUS/1.1 mode, disable all MD5-based attribute obfuscation and suppress
Message-Authenticator.

**Specific changes:**

#### 3a. User-Password (attribute 2)
- Currently: `AuthPacket.PwCrypt()` applies MD5-based obfuscation
- RADIUS/1.1: Send as plain `string` type (1-128 bytes), no obfuscation
- `AuthPacket.PwDecrypt()` must return raw bytes in 1.1 mode

#### 3b. Tunnel-Password (encrypt=2 attributes)
- Currently: `Packet.SaltCrypt()` applies salt + MD5 obfuscation
- RADIUS/1.1: Send as plain `string` type, no salt prefix, no length sub-field
- `Packet._EncodeValue()` checks `attr.encrypt == 2` — needs mode-aware bypass
- `Packet._DecodeValue()` calls `SaltDecrypt()` — needs mode-aware bypass

#### 3c. MS-MPPE-Send-Key / MS-MPPE-Recv-Key
- Currently: Vendor-specific attributes using similar MD5 obfuscation
- RADIUS/1.1: Plain `string` encoding
- Handled by the same `encrypt=2` path as Tunnel-Password

#### 3d. Message-Authenticator (attribute 80)
- Currently: Generated via HMAC-MD5 in `_refresh_message_authenticator()`
- RADIUS/1.1: Must never be sent; silently discard if received
- `DecodePacket()` currently sets `self.message_authenticator = True` when attr 80 is found
- `RequestPacket()` and `ReplyPacket()` call `_refresh_message_authenticator()` when set

#### 3e. Authenticator field in responses
- Currently: `ReplyPacket()` computes MD5-based Response Authenticator
- RADIUS/1.1: No authenticator computation — Token field copied from request, rest zeroed

**Files affected:**
- `pyrad2/packet.py` — All packet classes, encode/decode methods
- `pyrad2/radsec/client.py` — Password handling in EAP-MD5 flow

**Complexity:** Large. The MD5 obfuscation is deeply embedded in the packet encode/decode
pipeline. Each affected method needs a conditional path. The `encrypt=2` handling in
`_EncodeValue()` / `_DecodeValue()` is relatively clean to branch on, but the authenticator
and Message-Authenticator changes touch many methods.

### 4. Request/Response Matching — Medium

**What:** Replace ID-based matching with Token-based matching for RADIUS/1.1 connections.

**Current matching logic:**
- `Packet.VerifyReply()` checks `reply.id != self.id` and verifies MD5 authenticator
- RadSec client in `_send_packet()` calls `packet.VerifyReply(reply, response)`

**RADIUS/1.1 matching:**
- Match responses to requests by Token field value (4 bytes)
- No MD5 authenticator verification needed (TLS provides integrity)
- Token is set by sender, echoed by responder

**Files affected:**
- `pyrad2/packet.py` — `Packet.VerifyReply()`, `Packet.CreateReply()`
- `pyrad2/radsec/client.py` — `RadSecClient._send_packet()` reply verification
- `pyrad2/radsec/server.py` — `RadSecServer._handle_client()` reply construction

**Complexity:** Medium. The matching logic itself is simpler than the current MD5 approach.
The challenge is that `Packet` objects need to carry a Token field and know their protocol version.

### 5. Connection-Level State — Medium

**What:** Introduce per-connection state tracking for negotiated protocol version and Token counter.

**Current state:** The RadSec client creates a new TCP+TLS connection per `_send_packet()`
call — there is no persistent connection or connection-level state. The RadSec server
handles one packet per connection in `_handle_client()`.

**RADIUS/1.1 requirements:**
- Track negotiated ALPN version per connection
- Maintain a Token counter per connection (initialized to random value, incremented)
- Potentially maintain a duplicate-detection cache (Token → response, 5-30 second TTL)
- Session resumption must bind to the negotiated ALPN version

**Design options:**
1. **Connection wrapper class:** Create a `RadSecConnection` class that wraps the asyncio
   reader/writer, stores the negotiated version, Token counter, and dedup cache. Both client
   and server would use this.
2. **Inline state:** Add attributes directly to the client/server for the current connection.
   Simpler but less clean for connection pooling.

**Files affected:**
- `pyrad2/radsec/client.py` — Connection lifecycle
- `pyrad2/radsec/server.py` — Connection lifecycle
- New file possible: `pyrad2/radsec/connection.py`

**Complexity:** Medium. The current one-shot connection pattern in the RadSec client works
against persistent state, but the server already handles connections via `_handle_client()`.
A connection abstraction would benefit both.

### 6. CHAP-Challenge Handling — Small

**What:** In RADIUS/1.1, CHAP-Password must be accompanied by an explicit CHAP-Challenge
attribute since the Request Authenticator is no longer available for deriving the challenge.

**Current code:** `AuthPacket.VerifyChapPasswd()` checks for `CHAP-Challenge` in the packet
and falls back to `self.authenticator` — this fallback must be removed in 1.1 mode.

**Files affected:**
- `pyrad2/packet.py` — `AuthPacket.VerifyChapPasswd()`

**Complexity:** Small. One conditional check.

### 7. Protocol-Error Response — Small

**What:** Support sending Protocol-Error packets (Code 252, RFC 7930) when ALPN
negotiation fails.

**Details:**
- Add `ProtocolError = 252` to `PacketType` enum
- Support `Error-Cause` attribute (attribute 101) with value 406 (Unsupported Extension)
- Support `Reply-Message` attribute (attribute 18) with descriptive text
- Send with Token = all zeros

**Files affected:**
- `pyrad2/constants.py` — Add Protocol-Error code
- `pyrad2/radsec/server.py` — Error response handling
- `pyrad2/radsec/client.py` — Error response handling

**Complexity:** Small. Straightforward packet construction.

### 8. TLS 1.3 Enforcement — Small

**What:** When RADIUS/1.1 is configured, enforce TLS 1.3 as the minimum version.

**Current code:** `RadSecServer.setup_ssl()` and `RadSecClient.setup_ssl()` create SSL
contexts without version restrictions. The server also sets weak ciphers
(`DES-CBC3-SHA:RC4-SHA:AES128-SHA`) that are incompatible with TLS 1.3.

**Details:**
- Set `ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3` when RADIUS/1.1 is configured
- Remove or update the `ALLOWED_CIPHERS` constant — TLS 1.3 uses cipher suites differently
  and the current cipher list is insecure regardless of RFC 9765

**Files affected:**
- `pyrad2/radsec/client.py` — `setup_ssl()`
- `pyrad2/radsec/server.py` — `setup_ssl()`

**Complexity:** Small. Python's `ssl` module supports `minimum_version` directly.

### 9. DTLS Support — Not Feasible (currently)

**What:** RFC 9765 also covers RADIUS/1.1 over DTLS (UDP + TLS, port 2083/udp).

**Current state:** pyrad2 has no DTLS support. Python's stdlib `ssl` module does not
support DTLS. The UDP client/server (`client.py`, `server.py`, `server_async.py`) use raw
UDP sockets.

**What would be needed:**
- A DTLS library (e.g., `python-dtls`, `aioquic`, or OpenSSL bindings)
- Retransmission logic with Token-based deduplication
- DTLS session management

**Recommendation:** Defer DTLS entirely. RFC 9765 is primarily motivated by TLS, and DTLS
support would be a substantially larger effort requiring new dependencies. The TLS path
alone provides the security benefits.

### 10. Session Resumption / Down-Bidding Prevention — Medium

**What:** When TLS sessions are resumed, the ALPN negotiated on the original session must
be enforced. A RADIUS/1.1 session must not be resumed as RADIUS/1.0.

**Details:**
- Python's `ssl` module handles session tickets automatically with TLS 1.3
- Need to track the ALPN associated with a session and validate on resumption
- Client must advertise only `radius/1.1` when resuming a 1.1 session
- Server must close connection if a 1.1 session is resumed without proper ALPN

**Files affected:**
- `pyrad2/radsec/client.py` — Session resumption handling
- `pyrad2/radsec/server.py` — Session resumption validation

**Complexity:** Medium. Python's `ssl` module provides limited control over session
ticket management. May require `ssl.SSLContext.post_handshake_auth` or manual
session caching. TLS 1.3 session tickets are generally handled transparently, but
binding ALPN to them requires application-level tracking.

### 11. Tests — Medium

**What:** Unit and integration tests for all RADIUS/1.1 behavior.

**Needed tests:**
- ALPN negotiation (1.0 only, 1.1 only, both, mismatch scenarios)
- Packet encode/decode in 1.1 mode (header format, Token field)
- Token-based request/response matching
- User-Password encoding without MD5 in 1.1 mode
- Tunnel-Password encoding without salt/MD5 in 1.1 mode
- Message-Authenticator suppression in 1.1 mode
- CHAP-Challenge requirement in 1.1 mode
- Protocol-Error response generation
- Version mismatch handling (graceful connection closure)
- Mixed-mode: client and server supporting both versions
- Regression: ensure legacy RADIUS/TLS (1.0) still works identically

**Complexity:** Medium. Mostly follows existing test patterns in `tests/test_radsec_server.py`
and `tests/test_packet.py`. TLS tests may need mock SSL contexts or test certificates.

---

## Effort Summary

| Work item | Complexity | Estimated scope |
|---|---|---|
| 1. ALPN negotiation | Moderate | ~150 lines across client/server |
| 2. Packet header format | Large | ~300 lines in `packet.py` |
| 3. Attribute encoding changes | Large | ~200 lines in `packet.py` |
| 4. Request/response matching | Medium | ~100 lines |
| 5. Connection-level state | Medium | ~200 lines, possibly new module |
| 6. CHAP-Challenge handling | Small | ~10 lines |
| 7. Protocol-Error response | Small | ~50 lines |
| 8. TLS 1.3 enforcement | Small | ~20 lines |
| 9. DTLS support | Not feasible | Deferred — needs external library |
| 10. Session resumption guards | Medium | ~80 lines |
| 11. Tests | Medium | ~400 lines |
| **Total** | | **~1,500 lines of changes** |

---

## Risk Assessment

### Low risk
- **ALPN negotiation** — Well-supported by Python's `ssl` module, straightforward API
- **TLS 1.3 enforcement** — One-liner configuration change
- **Protocol-Error packets** — Simple packet construction
- **CHAP-Challenge** — Minimal code change

### Medium risk
- **Attribute encoding changes** — Requires careful conditional branching without breaking
  legacy mode. Risk of subtle bugs in password handling (security-sensitive).
- **Connection-level state** — The current architecture treats packets as independent
  objects. Introducing connection state requires design changes that touch multiple modules.
- **Session resumption** — Python's `ssl` module provides limited visibility into TLS
  session management.

### High risk
- **Packet header format changes** — This is the most structurally invasive change. The
  20-byte header is unpacked/packed in many places, and the semantic meaning of its fields
  changes entirely. Both encode and decode paths must be bifurcated cleanly.
  Incorrect implementation could cause silent protocol incompatibility.
- **Backward compatibility** — The entire implementation must support both 1.0 and 1.1
  simultaneously within the same process, negotiated per-connection. Bugs here could
  cause legacy connections to break.

---

## Recommended Implementation Strategy

### Phase 1: Foundation (items 5, 8, 7)
1. Create a `RadSecConnection` abstraction with protocol version and Token counter state
2. Add TLS 1.3 minimum version enforcement (configurable)
3. Add Protocol-Error packet code to constants

### Phase 2: ALPN Negotiation (items 1, 10)
1. Add `version` configuration to `RadSecClient` and `RadSecServer`
2. Implement ALPN protocol string configuration in SSL setup
3. Read negotiated version after TLS handshake
4. Handle version mismatch with appropriate errors
5. Add session resumption guards

### Phase 3: Packet Format (items 2, 4)
1. Add `protocol_version` attribute to `Packet` base class
2. Implement RADIUS/1.1 header encoding (Token + Reserved fields)
3. Implement RADIUS/1.1 header decoding
4. Implement Token-based request/response matching
5. Wire Token counter from connection state into packet creation

### Phase 4: Attribute Encoding (items 3, 6)
1. Bypass MD5 password obfuscation in 1.1 mode
2. Bypass salt encryption for Tunnel-Password in 1.1 mode
3. Suppress Message-Authenticator in 1.1 mode
4. Add CHAP-Challenge requirement in 1.1 mode

### Phase 5: Testing (item 11)
1. Unit tests for each changed behavior
2. Integration tests for client-server ALPN negotiation
3. Regression tests for legacy RADIUS/TLS mode

---

## Conclusion

Implementing RFC 9765 in pyrad2 is feasible and represents a meaningful security
improvement by eliminating MD5 from the application layer. The project already has the
right foundation: RadSec client/server with TLS on port 2083, asyncio-based networking,
and Python 3.12+ with full ALPN support in the `ssl` module.

The main challenge is structural: the `Packet` class hierarchy currently bakes in MD5
assumptions at every level (header authenticators, password obfuscation, message
authenticators, reply verification). Making these conditional on protocol version requires
touching nearly every method in `packet.py` while preserving backward compatibility for
legacy RADIUS/TLS.

DTLS support should be deferred — it requires a third-party library and is not needed
for the primary security benefits of RFC 9765.

The RFC itself notes that "only minor code changes are required to support RADIUS/1.1."
This is accurate for implementations that already have clean separation between transport
and packet encoding. In pyrad2's case, the packet layer and transport layer are more
tightly coupled (e.g., MD5 authenticator computation is embedded in `RequestPacket()`
and `ReplyPacket()`), so the effort is moderate rather than minor.
