# RFC 9765 Verified Implementation Plan for pyrad2

## Overview

This document is the product of a 5-agent review team that independently verified every
claim in the original evaluation (`docs/rfc9765-evaluation.md`). Each agent had a
specialized role:

1. **RFC 9765 Specification Analyst** — cross-referenced every claim against the actual RFC text
2. **Python SSL/ALPN Capabilities Expert** — verified all Python `ssl` module claims with live tests
3. **Codebase Impact Auditor** — traced every file, method, and line number against real code
4. **Devil's Advocate** — challenged architecture, security, estimates, and phasing
5. **Test Infrastructure Analyst** — mapped existing tests and gaps for RFC 9765

---

## PART 1: CORRECTIONS TO THE ORIGINAL EVALUATION

### Critical Error

| Item | Evaluation Claim | Actual Value | Source |
|------|-----------------|--------------|--------|
| Protocol-Error code | Code 252 | **Code 52** | RFC 7930 §4, IANA RADIUS Packet Type Codes registry |

This is a showstopper error. Code 252 falls in the "Experimental Use" range (250-253).
The correct Protocol-Error code is **52**, as defined in RFC 7930.

### Factual Inaccuracies

| Item | Evaluation Claim | Reality |
|------|-----------------|---------|
| Header packing | "All four methods use `struct.pack('!BBH16s', ...)`" | Only `AuthPacket.RequestPacket()` uses `!BBH16s`. The other three (`AcctPacket.RequestPacket()`, `CoAPacket.RequestPacket()`, `Packet.ReplyPacket()`) use `struct.pack('!BBH', ...)` and handle the authenticator separately. |
| `post_handshake_auth` | "May require `ssl.SSLContext.post_handshake_auth`" for ALPN binding | `post_handshake_auth` is for TLS 1.3 post-handshake *client certificate authentication*. It has nothing to do with ALPN binding or session resumption. |
| `set_ciphers()` and TLS 1.3 | Implied that weak `ALLOWED_CIPHERS` are "incompatible with TLS 1.3" | **Misleading.** `set_ciphers()` only affects TLS 1.2 and earlier. TLS 1.3 cipher suites are always available regardless of `set_ciphers()` calls. TLS 1.3 will still work. The ciphers are insecure for TLS 1.2 fallback, but they don't block TLS 1.3. |
| `set_ciphersuites()` | Devil's advocate claimed Python needs `set_ciphersuites()` for TLS 1.3 | **`set_ciphersuites()` does not exist in Python's `ssl` module.** TLS 1.3 suites are managed by OpenSSL automatically. |

### Omissions from the Original Evaluation

#### RFC Requirements Missed

1. **Original-Packet-Code attribute** (RFC 7930 §4) — MUST NOT be sent over RADIUS/1.1;
   MUST be treated as invalid if received. Not mentioned at all.

2. **Status-Server with Identifier=0** — RFC 9765 says the practice of using Identifier=0
   for Status-Server "MUST NOT be used for RADIUS/1.1." Not mentioned.

3. **Token deduplication** — RFC requires "implementations MUST do deduplication only on the
   Token field, not on any other field." Only vaguely alluded to in the evaluation.

4. **Token counter is client-side only** — RFC says tokens are incremented "for every unique
   new packet that is sent by the client." Servers echo the Token from requests. The
   evaluation describes token management generically without this distinction.

5. **Default version MUST be "1.0,1.1"** — The RFC has a normative MUST requirement that the
   default configuration advertises both versions. The evaluation proposes this as a default
   but does not cite it as normative.

#### Codebase Items Missed

6. **`pyrad2/client_async.py`** — completely absent from the module impact table. It imports
   from `packet.py`, uses `VerifyReply()` and `RequestPacket()`. Changes to these methods
   must not break this module.

7. **`_refresh_message_authenticator()` and `verify_message_authenticator()`** — both build
   partial headers with `struct.pack('!BBH', ...)` (lines 122 and 190). Not listed under
   header-format changes despite needing RADIUS/1.1 conditional paths.

8. **`hmac_new()` helper** (packet.py line 14) — module-level function hardcoding
   `digestmod="MD5"`. Not mentioned.

9. **`Packet._salt_en_decrypt()`** (line 582) — private helper with the actual `hashlib.md5()`
   call for both SaltCrypt/SaltDecrypt.

10. **Client/server cipher asymmetry** — server calls `set_ciphers()` but client does not.
    Different remediation needed for each.

11. **`Tunnel-Password` not in any dictionary file** — cannot test encrypt=2 changes for
    this real-world attribute without adding it.

12. **`Error-Cause` (attribute 101) not in any dictionary file** — needed for Protocol-Error
    packets.

13. **Existing bug: `packet.verify()` does not exist** — `radsec/server.py` line 164 calls
    `packet.verify()` but no such method exists on any Packet class. Would raise
    `AttributeError` at runtime when `verify_packet=True`.

14. **`parse_packet()` needs protocol_version parameter** — currently takes
    `(data, secret, dictionary)` with no way to know the connection's negotiated version.

15. **`Packet.__init__()` unconditionally calls `CreateID()`** — in RADIUS/1.1 mode,
    the ID field is Reserved-1 (always zero). Without modification, every 1.1 packet gets
    a non-zero ID, violating the RFC.

---

## PART 2: VERIFIED PYTHON SSL CAPABILITIES

All capabilities verified on Python 3.11.14 with OpenSSL 3.0.13. All APIs needed
exist since Python 3.5-3.8 (well within pyrad2's 3.12+ requirement).

| Feature | API | Status | Notes |
|---------|-----|--------|-------|
| ALPN protocol setting | `ssl_ctx.set_alpn_protocols(['radius/1.0', 'radius/1.1'])` | **Works** | Available on both client and server contexts |
| ALPN result reading | `ssl_object.selected_alpn_protocol()` | **Works** | Returns string or `None` |
| ALPN via asyncio | `writer.get_extra_info('ssl_object').selected_alpn_protocol()` | **Works** | Verified with actual TLS 1.3 connection |
| TLS 1.3 enforcement | `ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3` | **Works** | |
| Session ticket control | `ssl_ctx.num_tickets` | **Works** | Default 2, can set to 0 to disable |
| Session object access | `ssl_object.session` | **Works** | Readable and settable |
| ALPN on session tickets | N/A | **NOT POSSIBLE** | `SSLSession` exposes `[has_ticket, id, ticket_lifetime_hint, time, timeout]` — no ALPN field. ALPN binding must be tracked at the application layer. |
| Session reuse via asyncio | `ssl_object.session = saved_session` | **IMPRACTICAL** | `asyncio.open_connection()` completes the handshake before returning. By the time you have the ssl_object, it's too late to set the session. Would need `loop.create_connection()` with custom protocol. |

### Key Insight: ALPN No-Match Behavior

When ALPN lists don't overlap, OpenSSL/Python behavior varies:
- **TLS 1.2**: Handshake may succeed with `selected_alpn_protocol()` returning `None`
- **TLS 1.3 with OpenSSL 3.x**: Server may abort handshake (implementation-dependent)

This means ALPN mismatch detection **must** check `selected_alpn_protocol()` after every
handshake, not rely on the TLS layer to reject mismatches.

### Key Insight: `set_ciphers()` Does Not Affect TLS 1.3

Tested and confirmed: `set_ciphers('DES-CBC3-SHA:RC4-SHA:AES128-SHA')` on a TLS 1.3
context results in 4 total ciphers: 3 TLS 1.3 suites (always present) + 1 legacy suite.
TLS 1.3 ciphers are controlled by OpenSSL, not by `set_ciphers()`.

---

## PART 3: VERIFIED WORK ITEMS WITH CORRECTIONS

### Work Item 1: ALPN Negotiation — Moderate (CONFIRMED)

**Verified correct.** Python's `ssl` module fully supports ALPN. The implementation is
straightforward.

**Additional requirements identified:**
- Must check `selected_alpn_protocol()` after EVERY handshake (cannot rely on TLS-level rejection)
- Default MUST be `["radius/1.0", "radius/1.1"]` per RFC normative requirement
- Must handle `selected_alpn_protocol() == None` (legacy client without ALPN)
- ALPN selection follows client preference order in Python/OpenSSL (not server preference)

**Files:** `radsec/client.py:setup_ssl()`, `radsec/server.py:setup_ssl()`, `_handle_client()`, `_send_packet()`

### Work Item 2: Packet Header Format — Large (CONFIRMED, expanded scope)

**Verified correct in concept, but scope is larger than described.**

Methods that pack/unpack headers (all need RADIUS/1.1 conditional paths):
- `Packet.DecodePacket()` — line 543: `struct.unpack("!BBH16s", ...)`
- `AuthPacket.RequestPacket()` — lines 716, 731: `struct.pack("!BBH16s", ...)`
- `AcctPacket.RequestPacket()` — line 915: `struct.pack("!BBH", ...)` + separate authenticator
- `CoAPacket.RequestPacket()` — line 985: `struct.pack("!BBH", ...)` + separate authenticator
- `Packet.ReplyPacket()` — line 410: `struct.pack("!BBH", ...)` + MD5 authenticator
- `Packet._refresh_message_authenticator()` — line 122: `struct.pack("!BBH", ...)` **(MISSED by eval)**
- `Packet.verify_message_authenticator()` — line 190: `struct.pack("!BBH", ...)` **(MISSED by eval)**

**Additional changes needed:**
- `Packet.__init__()` — must skip `CreateID()` in 1.1 mode, set `self.id = 0`
- `parse_packet()` — needs `protocol_version` parameter (API break)
- All `CreateReply()` methods — must copy Token instead of authenticator
- New `token` attribute on Packet class

**Revised estimate:** ~350-400 lines (was 300)

### Work Item 3: Attribute Encoding — Large (CONFIRMED)

**Verified correct.** All MD5 paths identified in the evaluation are accurate.

**Additional items:**
- `Packet._salt_en_decrypt()` (line 582) — private MD5 helper used by both Salt methods
- `hmac_new()` (line 14) — module-level MD5 helper used by Message-Authenticator
- In 1.1 mode, `add_message_authenticator()` should be a no-op (not just suppress at send time)
- In 1.1 mode, `DecodePacket()` must silently discard attribute 80 (currently stores it)

### Work Item 4: Request/Response Matching — Medium (CONFIRMED)

**Verified correct.**

### Work Item 5: Connection-Level State — Medium-Large (UPGRADED)

**Complexity underestimated.** Key issues raised by devil's advocate:

1. **Token flow problem:** The connection has the token counter, but `RequestPacket()` needs
   the token. Tokens must be injected into packets before encoding. This creates a
   cross-layer dependency between transport (RadSec) and packet (Packet class) that doesn't
   currently exist.

2. **One-connection-per-packet:** The current RadSec client creates a new TCP+TLS connection
   for every `_send_packet()` call. With RADIUS/1.1, each connection has its own token
   counter starting from a random value. This means every request gets a unique random
   token anyway — the counter mechanism degenerates. The RFC's token counter design
   assumes persistent connections with multiple packets.

3. **Server single-packet handling:** `_handle_client()` reads one packet and returns. For
   RADIUS/1.1 to be meaningful, the server needs a loop to handle multiple packets per
   connection.

**Decision needed:** Does the implementation require connection persistence/multiplexing?
- **Without it:** Functional but doesn't deliver the scalability benefits of RADIUS/1.1
- **With it:** Significantly larger scope (~2-3x for connection management)
- **Recommendation:** Implement without persistent connections first (minimum viable), add
  connection pooling/multiplexing as a follow-up. Document the limitation.

**Revised estimate:** ~250-300 lines (was 200)

### Work Item 6: CHAP-Challenge — Small (CONFIRMED)

**Verified correct.** One conditional check in `VerifyChapPasswd()` at line 832-834.

### Work Item 7: Protocol-Error — Small (CORRECTED)

**Code number is WRONG in the evaluation.** Must be `ProtocolError = 52` (not 252).

Additional requirements:
- `Original-Packet-Code` attribute (RFC 7930) MUST NOT be sent over RADIUS/1.1
- Token field MUST be all zeros in Protocol-Error packets
- `Error-Cause` attribute (101) must be added to dictionary files

### Work Item 8: TLS 1.3 Enforcement — Small (CORRECTED)

**Simpler than described.** Key findings:
- `set_ciphers()` does NOT affect TLS 1.3. The `ALLOWED_CIPHERS` constant is irrelevant
  for TLS 1.3 connections. TLS 1.3 suites are always available.
- `set_ciphersuites()` does NOT exist in Python's `ssl` module.
- Only needed: `ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3`
- The `ALLOWED_CIPHERS` should still be fixed for TLS 1.2 fallback security, but that's
  a separate concern from RFC 9765.

### Work Item 9: DTLS — Not Feasible (CONFIRMED)

**Verified.** Zero DTLS references in codebase. Python `ssl` module has no DTLS support.

### Work Item 10: Session Resumption / Down-Bidding Prevention — Difficult (UPGRADED)

**More difficult than described.** Verified findings:

- `SSLSession` object exposes `[has_ticket, id, ticket_lifetime_hint, time, timeout]` — **no ALPN field**
- Cannot bind ALPN to a session ticket at the Python level
- `asyncio.open_connection()` completes the handshake before returning, so you cannot
  set the session object before resumption
- **Workaround:** Application-level tracking — store ALPN alongside session ID in a dict,
  validate after every handshake that the negotiated ALPN matches the stored one
- Setting `num_tickets = 0` can disable session tickets entirely as a nuclear option

**Recommendation:** Implement application-level ALPN tracking per session ID. Accept that
Python's ssl module makes this imperfect. Document the limitation.

### Work Item 11: Tests — Medium-Large (UPGRADED)

**Scope significantly larger than estimated.** Test infrastructure analyst found:

- **Zero existing TLS integration tests** — the RadSec tests only test handler methods,
  never establish actual TLS connections
- **56 new tests needed** across 11 categories
- **~730 lines** (was 400)
- Missing dictionary entries for `Tunnel-Password` and `Error-Cause` needed for tests
- Existing test certificates support TLS 1.3 (RSA 2048-bit, SHA-256, valid until 2026-07)
- No `conftest.py` exists — shared fixtures needed

---

## PART 4: SECURITY REQUIREMENTS (from Devil's Advocate)

These are mandatory prerequisites before enabling RADIUS/1.1:

### S1. Plaintext Password Safety Guard (CRITICAL)

In RADIUS/1.1 mode, `PwCrypt()` becomes a no-op (plaintext). If someone creates a packet
with `protocol_version="1.1"` and sends it over the UDP `Client` (not RadSec), the password
travels in cleartext over the network with no encryption.

**Required mitigation:** `RequestPacket()` in RADIUS/1.1 mode should raise an error if
invoked outside a TLS context, OR the `protocol_version` should only be settable by the
RadSec transport layer, not by end users.

### S2. `ssl.CERT_NONE` Must Not Be Allowed with RADIUS/1.1 (CRITICAL)

The RadSec server defaults to `verify_mode=ssl.CERT_NONE`. In RADIUS/1.1 mode, TLS is
the **sole security layer** — no MD5, no shared secret, no Message-Authenticator. With
`CERT_NONE`, any network client can send RADIUS packets with no authentication.

**Required:** RADIUS/1.1 mode must refuse to start with `CERT_NONE`. Default to
`ssl.CERT_REQUIRED` when version includes "1.1".

### S3. Backward Compatibility Contract (HIGH)

The evaluation does not specify default behavior. If a user upgrades pyrad2 and changes
nothing:
- `RadSecClient()` would suddenly advertise ALPN (behavioral change)
- `RadSecServer()` would suddenly require ALPN support from clients

**Required:** The safe default must be `None` (no ALPN, legacy behavior) with explicit
opt-in, OR document the breaking change prominently.

**However:** RFC 9765 has a MUST for default "1.0,1.1". This conflicts with backward
compatibility. Resolution: add the `version` parameter but default to `None` (legacy)
with a deprecation warning, planning to switch to "1.0,1.1" in a future major version.

---

## PART 5: REVISED IMPLEMENTATION STRATEGY

### Revised Phasing (addressing devil's advocate critique)

The original Phase 3/4 split is dangerous — Phase 3 alone produces non-conformant packets
in 1.1 mode (correct header but still computes MD5 authenticators and Message-Authenticator).
Phases 3 and 4 must be atomic.

#### Phase 1: ALPN + TLS 1.3 (items 1, 8, 7)
1. Add `version` parameter to `RadSecClient` and `RadSecServer` (default: `None`)
2. Configure ALPN in `setup_ssl()` based on version
3. Read `selected_alpn_protocol()` after handshake via `writer.get_extra_info('ssl_object')`
4. Set `ssl_ctx.minimum_version = TLSv1_3` when version includes "1.1"
5. Add `ProtocolError = 52` to `PacketType` enum
6. Add `Error-Cause` (101) to dictionary files
7. Enforce `CERT_REQUIRED` when version includes "1.1"
8. **Tests for this phase** (~120 lines)

#### Phase 2: Packet Format + Attribute Encoding (items 2, 3, 4, 6) — ATOMIC
1. Add `protocol_version` and `token` attributes to `Packet.__init__()`
2. Skip `CreateID()` in 1.1 mode (set `self.id = 0`)
3. Implement 1.1 header encoding in all `RequestPacket()` and `ReplyPacket()` methods
4. Implement 1.1 header decoding in `DecodePacket()`
5. Bypass MD5 in `PwCrypt()`/`PwDecrypt()` for 1.1 mode
6. Bypass salt encryption in `_EncodeValue()`/`_DecodeValue()` for 1.1 mode
7. Suppress Message-Authenticator in 1.1 mode (add_message_authenticator, decode, refresh)
8. Implement Token-based `VerifyReply()` for 1.1 mode
9. Copy Token in `CreateReply()` for 1.1 mode
10. Require CHAP-Challenge in 1.1 mode in `VerifyChapPasswd()`
11. Add `protocol_version` parameter to `parse_packet()`
12. Add safety guard: raise error if 1.1 packet encoded outside TLS context
13. **Tests for this phase** (~350 lines)

#### Phase 3: Connection Integration (item 5)
1. Create connection-level state (Token counter, negotiated version)
2. Wire ALPN result from Phase 1 into packet creation from Phase 2
3. Token injection: connection assigns token to packet before `RequestPacket()`
4. Update `_send_packet()` to set `protocol_version` on packets based on ALPN
5. Update `_handle_client()` to set `protocol_version` on parsed packets
6. Application-level ALPN-session tracking for down-bidding prevention (item 10)
7. **Tests for this phase** (~150 lines)

#### Phase 4: Hardening + Regression (item 11 remainder)
1. End-to-end integration tests (real TLS loopback)
2. Regression tests ensuring RADIUS/1.0 is unchanged
3. Add `Tunnel-Password` to test dictionaries
4. Edge case tests (malformed packets, version mismatches)
5. Fix existing `packet.verify()` bug in radsec/server.py
6. **Remaining tests** (~110 lines)

### Revised Effort Summary

| Work area | Original estimate | Revised estimate | Reason for change |
|-----------|------------------|-----------------|-------------------|
| ALPN negotiation | ~150 lines | ~150 lines | Confirmed |
| Packet header format | ~300 lines | ~400 lines | Missed methods (_refresh_message_authenticator, verify_message_authenticator, __init__, parse_packet) |
| Attribute encoding | ~200 lines | ~200 lines | Confirmed |
| Request/response matching | ~100 lines | ~100 lines | Confirmed |
| Connection-level state | ~200 lines | ~300 lines | Token flow cross-layer, ALPN session tracking |
| CHAP-Challenge | ~10 lines | ~10 lines | Confirmed |
| Protocol-Error (code 52) | ~50 lines | ~60 lines | Original-Packet-Code prohibition added |
| TLS 1.3 enforcement | ~20 lines | ~15 lines | Simpler than thought (set_ciphers irrelevant for TLS 1.3) |
| Session resumption | ~80 lines | ~100 lines | Application-level tracking needed |
| Security guards | (not in original) | ~40 lines | Plaintext password guard, CERT_REQUIRED enforcement |
| Tests | ~400 lines | ~730 lines | Zero existing TLS integration tests, 56 new test cases |
| **Total** | **~1,510 lines** | **~2,105 lines** | **~39% increase** |

---

## PART 6: RISK REGISTER (VERIFIED)

### Resolved Risks

| Risk | Resolution |
|------|-----------|
| "Are Python ALPN APIs available?" | **Yes.** Verified working on Python 3.11+ with OpenSSL 3.x. All APIs exist since Python 3.5-3.8. |
| "Can you read ALPN from asyncio StreamWriter?" | **Yes.** `writer.get_extra_info('ssl_object').selected_alpn_protocol()` works and returns `'radius/1.1'` in test. |
| "Are test certificates TLS 1.3 compatible?" | **Yes.** RSA 2048-bit, SHA-256 certificates work with TLS 1.3. |
| "Does set_ciphers break TLS 1.3?" | **No.** `set_ciphers()` only affects TLS 1.2 and earlier. TLS 1.3 suites are always present. |

### Active Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Session ticket ALPN binding not natively supported in Python | Medium | Application-level tracking by session ID |
| One-connection-per-packet defeats Token counter purpose | Medium | Document limitation; add connection pooling in future version |
| `self.authenticator` semantics unclear in 1.1 mode | High | Design decision: store Token in bytes 0-3, zero bytes 4-15 of authenticator field for backward compat |
| 19+ methods need conditional branching | Medium | Accept as least-bad option; subclass hierarchy would be worse |
| EAP-MD5 uses MD5 at EAP layer (not RADIUS layer) | Low | EAP-MD5 challenge/response is unchanged by RFC 9765; only suppress the HMAC-MD5 Message-Authenticator that wraps EAP packets |
| Server cert expires 2026-07-09 | Low | Regenerate test certificates before expiry |

---

## APPENDIX: Existing Bug Found During Review

**File:** `pyrad2/radsec/server.py` line 164
**Bug:** `packet.verify()` is called but no `verify()` method exists on any Packet class.
Available methods are `VerifyPacket()`, `VerifyReply()`, `VerifyAuthRequest()`,
`VerifyAcctRequest()`, `VerifyCoARequest()`, and `verify_message_authenticator()`.
This would raise `AttributeError` at runtime when `verify_packet=True`.
**Recommendation:** Fix as part of Phase 1 by routing to the appropriate verify method
based on packet type.
