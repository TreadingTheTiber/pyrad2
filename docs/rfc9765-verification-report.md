# RFC 9765 Evaluation Verification Report

This document cross-references every technical claim in
`/home/user/pyrad2/docs/rfc9765-evaluation.md` against the actual text of
[RFC 9765](https://www.rfc-editor.org/rfc/rfc9765.html).

---

## (a) RFC Status and Date

**Evaluation claims:** "April 2025, Experimental"

**RFC says:** Published April 2025, Category: Experimental, Stream: IETF.
Updates: RFCs 2865, 2866, 5176, 6613, 6614, and 7360.

**Verdict: CORRECT.** The evaluation also correctly notes the RFC updates several
earlier RFCs (mentioned implicitly by referencing RFC 2865, 2868, etc.).

---

## (b) ALPN Protocol Strings

**Evaluation claims:** `radius/1.0` and `radius/1.1`

**RFC says:** IANA has registered two ALPN Protocol IDs:
- `radius/1.0` (hex: `0x72 0x61 0x64 0x69 0x75 0x73 0x2f 0x31 0x2e 0x30`)
- `radius/1.1` (hex: `0x72 0x61 0x64 0x69 0x75 0x73 0x2f 0x31 0x2e 0x31`)

**Verdict: CORRECT.**

---

## (c) Header Format and Byte Offsets

**Evaluation claims (line 86-93):**
```
Code(1) | Reserved-1(1, zero) | Length(2) | Token(4) | Reserved-2(12, zero)
```
And states: "Token from bytes 4-8 and ignores bytes 8-20"

**RFC says (Section 4.1):**
```
Byte 0:    Code (1 octet)
Byte 1:    Reserved-1 (1 octet) — "MUST be set to zero"
Bytes 2-3: Length (2 octets)
Bytes 4-7: Token (4 octets)
Bytes 8-19: Reserved-2 (12 octets) — "reserved for future protocol extensions"
Bytes 20+: Attributes
```

The RFC also states: "This field was previously used as the 'Identifier' in
historic RADIUS/TLS. It is now unused, as the Token field replaces it."

**Verdict: CORRECT.** The evaluation's byte offsets (4-8 for Token, 8-20 for
Reserved-2) are accurate. The header description including Reserved-1 being
"formerly Identifier" is consistent with the RFC. The total header remains 20
bytes.

---

## (d) Token Management — "Counter-Based"

**Evaluation claims (line 17, 105-108):** "Token (4-byte, counter-based)" and
"Initialize a random 32-bit counter when a connection opens. Increment for each
new packet sent on that connection."

**RFC says (Section 4.2.1):**
> "The Token values MUST be generated from a 32-bit counter that is unique to
> each connection. Such a counter SHOULD be initialized to a random value, taken
> from a random number generator, whenever a new connection is opened. The
> counter MUST then be incremented for every unique new packet that is sent by
> the client."

**Verdict: CORRECT.** The evaluation accurately describes counter-based token
generation. One nuance the evaluation does not explicitly call out: the RFC
says "sent by the client" — the counter increment language is specifically about
client-originated packets. For responses, the server echoes the Token from the
request (implied by the request/response matching semantics).

**Additional detail from RFC:** "The Token field MUST change for every new unique
packet that is sent on the same connection." And for DTLS: "the Token value MUST
NOT be changed when a duplicate packet is (re)sent."

---

## (e) User-Password Handling in RADIUS/1.1

**Evaluation claims (line 18, 131):** "Plaintext string (TLS protects it)" and
"Send as plain `string` type (1-128 bytes), no obfuscation"

**RFC says (Section 5.1.1):**
> "The User-Password attribute (RFC2865, Section 5.2) MUST be encoded the same
> as any other attribute of data type 'string' (RFC8044, Section 3.5). The
> contents of the User-Password field MUST be at least one octet in length and
> MUST NOT be more than 128 octets in length."

**Verdict: CORRECT.** The evaluation's description of "plaintext string 1-128
bytes" accurately reflects the RFC. The key change is that the MD5-based
obfuscation (XOR with MD5 hash of shared secret + authenticator) is completely
removed — the password is sent as a plain `string` data type, with TLS providing
confidentiality.

---

## (f) Tunnel-Password in RADIUS/1.1

**Evaluation claims (line 19, 135-136):** "Plain string, no salt" and "no salt
prefix, no length sub-field"

**RFC says (Section 5.1.3):**
> "The Tunnel-Password attribute...MUST be encoded the same as any other
> attribute of data type 'string' that contains a tag, such as
> Tunnel-Client-Endpoint."
>
> "Since the attribute is no longer obfuscated in RADIUS/1.1, there is no need
> for a Salt field or Data-Length fields...The textual value...can simply be
> encoded as is."

**Verdict: CORRECT.** The evaluation accurately describes the removal of both
the Salt field and the Data-Length sub-field. The attribute is encoded as a
tagged string.

---

## (g) Message-Authenticator Handling

**Evaluation claims (line 21, 147):** "Prohibited (silently discarded)" and
"Must never be sent; silently discard if received"

**RFC says (Section 5.2):**
> "The Message-Authenticator attribute...MUST NOT be sent over a RADIUS/1.1
> connection. That attribute is not used or needed in RADIUS/1.1."
>
> "If the Message-Authenticator attribute is received over a RADIUS/1.1
> connection, the attribute MUST be silently discarded or treated as an
> 'invalid attribute.'"

**Verdict: CORRECT.** The evaluation's summary of "prohibited (silently
discarded)" accurately captures both the sending prohibition ("MUST NOT be
sent") and the receiving behavior ("MUST be silently discarded or treated as
an 'invalid attribute'"). The evaluation's table uses "Prohibited" which is a
reasonable shorthand for "MUST NOT be sent."

---

## (h) TLS Version Requirement

**Evaluation claims (line 23):** "TLS 1.3+ required"

**RFC says:**
> "Implementations of this specification MUST require TLS version 1.3 or later."

**Verdict: CORRECT.** This is a hard MUST requirement, not merely a
recommendation. The evaluation is accurate.

---

## (i) Protocol-Error Code and Error-Cause

**Evaluation claims (line 230-238):** "Protocol-Error packets (Code 252, RFC
7930)" and "Error-Cause attribute (attribute 101) with value 406 (Unsupported
Extension)" and "Send with Token = all zeros"

**RFC 9765 says (Section 3.3.1):**
> "the end requiring ALPN MAY send a Protocol-Error packet [RFC7930]...The
> packet SHOULD also contain an Error-Cause attribute, with value 406
> (Unsupported Extension)...the Token field of the Protocol-Error packet cannot
> be copied from any request; therefore, that field MUST be set to all zeros."

**RFC 7930 says:** Protocol-Error is registered as **Code 52** (not 252).
IANA "RADIUS Packet Type Codes" registry confirms: Protocol-Error = 52.

**Verdict: DISCREPANCY.** The evaluation claims Protocol-Error is Code 252.
This is **WRONG**. The correct code is **52**, as defined by RFC 7930 Section 4
and confirmed in the IANA registry. Codes 250-253 are reserved for
"Experimental Use" in the IANA registry — 252 is NOT Protocol-Error.

The Error-Cause value 406 (Unsupported Extension) and Token = all zeros are
both **CORRECT**.

---

## (j) Session Resumption and ALPN Binding

**Evaluation claims (line 197, 285-299):** "Session resumption must bind to the
negotiated ALPN version" and "Client must advertise only `radius/1.1` when
resuming a 1.1 session" and "Server must close connection if a 1.1 session is
resumed without proper ALPN"

**RFC says (Section 3.5):**
> "RADIUS systems that negotiate the 'radius/1.1' protocol MUST associate that
> information with the session ticket and enforce the use of 'radius/1.1' on
> session resumption...both clients and servers MUST behave as if the RADIUS/1.1
> variable was set to 'require' for that session."
>
> "A client that is resuming a 'radius/1.1' connection MUST advertise only the
> capability to do 'radius/1.1' for the resumed session."

**Verdict: CORRECT.** The evaluation accurately describes the anti-downgrade
protection for session resumption.

---

## (k) CHAP-Challenge in RADIUS/1.1

**Evaluation claims (line 217-221):** "CHAP-Password must be accompanied by an
explicit CHAP-Challenge attribute since the Request Authenticator is no longer
available" and the fallback to `self.authenticator` "must be removed in 1.1
mode"

**RFC says (Section 5.1.2):**
> "Clients that send a CHAP-Password attribute in an Access-Request packet over
> a RADIUS/1.1 connection MUST also include a CHAP-Challenge attribute."
>
> "If the received Access-Request packet contains a CHAP-Password attribute but
> no CHAP-Challenge attribute, the proxy MUST create a CHAP-Challenge attribute
> in the proxied packet using the contents from the incoming Request
> Authenticator."

**Verdict: CORRECT.** The evaluation correctly identifies that the Request
Authenticator fallback for CHAP challenge derivation is no longer available in
RADIUS/1.1 because the Authenticator field has been replaced by Token +
Reserved-2. The proxy behavior note is an additional detail the evaluation
does not mention but is not strictly needed for a client/server library.

---

## (l) DTLS References

**Evaluation claims (line 265-280):** "RFC 9765 also covers RADIUS/1.1 over
DTLS (UDP + TLS, port 2083/udp)" and recommends deferring DTLS.

**RFC says (multiple sections):**
- Section 4.2.1: "For DTLS transport, it is possible to retransmit duplicate
  packets, in which case the Token value MUST NOT be changed when a duplicate
  packet is (re)sent."
- Section 4.2.2: "Where RADIUS does not require deduplication (e.g., TLS
  transport), the server SHOULD NOT do deduplication. However, DTLS transport
  is UDP-based, and therefore still requires deduplication."
- The title itself references "(D)TLS" throughout.

**Verdict: CORRECT.** The RFC does cover DTLS. The evaluation's recommendation
to defer DTLS is a reasonable implementation decision given Python's lack of
stdlib DTLS support.

---

## (m) Shared Secret in RADIUS/1.1

**Evaluation claims (line 22):** "Not used at application layer"

**RFC says (Section 1/3):**
> "All uses of the RADIUS shared secret have been removed."
>
> "there is no need to hide the contents of an attribute on a hop-by-hop
> basis...there is no need for any attribute to be obfuscated on a hop-by-hop
> basis using the previous methods defined for RADIUS."

**Verdict: CORRECT.** The shared secret is completely eliminated at the
application layer for RADIUS/1.1. The RFC does NOT mention setting the shared
secret to any fixed value (like "radsec") — the concept is simply removed
entirely.

---

## (n) Requirements the Evaluation MISSED

### 1. Original-Packet-Code Attribute Prohibition
**RFC Section 5.5:**
> "the Original-Packet-Code attribute (RFC7930, Section 4) MUST NOT be sent
> over a RADIUS/1.1 connection. If it is received in a packet, it MUST be
> treated as an 'invalid attribute.'"

The evaluation does not mention the Original-Packet-Code attribute at all.
This is a concrete requirement that should be implemented.

### 2. Status-Server Prohibition
**RFC Section 6.2:**
> "This practice MUST NOT be used for RADIUS/1.1, as the Identifier field is
> not used in this transport profile."

The evaluation does not mention that Status-Server (using Identifier = 0) is
prohibited in RADIUS/1.1. While Status-Server may not be implemented in pyrad2
currently, this is a normative requirement that should be documented.

### 3. Deduplication Requirements
**RFC Section 4.2.2:**
> "When using RADIUS/1.1, implementations MUST do deduplication only on the
> Token field, not on any other field."

The evaluation mentions duplicate-detection cache briefly (line 197) but does
not call out the explicit requirement that deduplication must be Token-only.

### 4. Default Version Configuration
**RFC Section 3.3:**
> "Implementations SHOULD support both historic RADIUS/TLS and RADIUS/1.1...
> MUST set the default value...to '1.0, 1.1'."

The evaluation's proposed default of `"1.0,1.1"` (line 67) is consistent with
this, but the evaluation does not cite the RFC's MUST requirement for this
default.

### 5. Proxy Behavior
**RFC Section 6.3** describes how proxies may negotiate different RADIUS
versions on different connections. The evaluation mentions proxies only in the
context of `pyrad2/proxy.py` being UDP-only and unaffected. If pyrad2 ever
supports TLS proxying, the proxy-specific requirements from Section 6.3 and
the CHAP-Challenge proxy behavior from Section 5.1.2 would need to be
implemented.

### 6. MS-MPPE Key Encoding
**RFC Section 5.1.4:**
> MS-MPPE-Send-Key and MS-MPPE-Recv-Key attributes "MUST be encoded as any
> other attribute of data type 'string'" without obfuscation.

The evaluation does mention this (line 20, 142-143) under "MS-MPPE keys" and
notes it's "Handled by the same `encrypt=2` path as Tunnel-Password." This is
correct.

### 7. Token Counter Language — Client vs. Both Sides
**RFC Section 4.2.1:**
> "The counter MUST then be incremented for every unique new packet that is
> sent by the client."

The evaluation describes Token management generically for "each new packet sent
on that connection" (line 106). The RFC specifically says "by the client."
Servers echo the Token from the request in their response. This distinction
matters for implementation: the server does NOT maintain its own counter for
response packets — it copies the Token from the request.

### 8. Version Configuration Variable
**RFC Section 3.2** defines a `Version` configuration variable with specific
semantics. The evaluation proposes a `version` parameter (line 67) accepting
`"1.0"`, `"1.1"`, or `"1.0,1.1"`. The RFC uses similar values but also
defines behavior when `Version` is "unset" (no ALPN strings sent, historic
RADIUS/TLS used). The evaluation should account for the "unset" case.

### 9. Connection Closure on ALPN Mismatch
**RFC Section 3.3.1:**
> "the end requiring ALPN...MUST close the connection"

The evaluation mentions "Handle version mismatch: close connection with
appropriate error" (line 71), which is consistent but could be more specific
about the Protocol-Error packet that MAY be sent before closing.

---

## Summary of Discrepancies

| # | Claim | Evaluation | RFC | Severity |
|---|-------|-----------|-----|----------|
| 1 | Protocol-Error code | 252 | **52** (RFC 7930, IANA registry) | **HIGH** — would cause wrong packet code |
| 2 | Token counter scope | "each new packet sent" (generic) | "sent by the client" (specific) | **MEDIUM** — server echoes request Token |
| 3 | Original-Packet-Code | Not mentioned | MUST NOT be sent in RADIUS/1.1 | **LOW** — missing requirement |
| 4 | Status-Server prohibition | Not mentioned | MUST NOT use in RADIUS/1.1 | **LOW** — missing requirement |
| 5 | Deduplication rule | Briefly mentioned | MUST deduplicate only on Token | **LOW** — under-specified |

---

## Conclusion

The evaluation at `/home/user/pyrad2/docs/rfc9765-evaluation.md` is
**substantially accurate** in its technical analysis. The header format, ALPN
strings, attribute encoding changes, TLS 1.3 requirement, session resumption
binding, CHAP-Challenge rules, Message-Authenticator handling, and shared
secret removal are all correctly described.

The single **critical error** is the Protocol-Error packet code: the evaluation
states Code 252, but the correct value is **Code 52** as defined by RFC 7930
and confirmed in the IANA RADIUS Packet Type Codes registry. This must be
corrected before implementation.

The evaluation is also missing a few minor requirements (Original-Packet-Code
prohibition, Status-Server prohibition, Token-only deduplication rule) that
should be added to the implementation work items for completeness.
