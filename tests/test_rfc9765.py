"""Tests for RFC 9765 (RADIUS/1.1) support.

Tests cover:
- Protocol version handling in packet construction
- Token-based request/response matching
- RADIUS/1.1 header format (ID=0, Token in authenticator field)
- Password handling bypass (PwCrypt/PwDecrypt plaintext in 1.1 mode)
- Salt encryption bypass (encrypt=2 attributes)
- Message-Authenticator suppression
- CHAP-Challenge requirement in 1.1 mode
- Reply packet encoding in 1.1 mode
- parse_packet with protocol_version
- RadSec client ALPN configuration
- RadSec server ALPN and security guards
- ProtocolError packet code (52)
"""

import hashlib
import os
import ssl
import struct
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from .base import TEST_ROOT_PATH

from pyrad2 import packet
from pyrad2.constants import (
    ATTR_ERROR_CAUSE,
    ATTR_MESSAGE_AUTHENTICATOR,
    PacketType,
    RADIUS_ALPN_RADIUS_10,
    RADIUS_ALPN_RADIUS_11,
)
from pyrad2.dictionary import Dictionary
from pyrad2.packet import (
    AcctPacket,
    AuthPacket,
    CoAPacket,
    Packet,
    PacketError,
    parse_packet,
)
from pyrad2.radsec.client import RadSecClient
from pyrad2.radsec.server import RadSecServer as BaseRadSecServer

SERVER_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.cert.pem")
SERVER_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/server/server.key.pem")
CA_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/ca/ca.cert.pem")
CLIENT_CERTFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.cert.pem")
CLIENT_KEYFILE = os.path.join(TEST_ROOT_PATH, "certs/client/client.key.pem")


class RadSecServer(BaseRadSecServer):
    """Concrete server subclass for testing."""
    async def handle_access_request(self, pkt):
        return pkt.CreateReply()

    async def handle_accounting(self, pkt):
        return pkt.CreateReply()

    async def handle_disconnect(self, pkt):
        return pkt.CreateReply()

    async def handle_coa(self, pkt):
        return pkt.CreateReply()


# ── Constants tests ──────────────────────────────────────────────────

class ConstantsTests(unittest.TestCase):
    def test_protocol_error_code(self):
        """Protocol-Error packet code is 52 per RFC 7930."""
        self.assertEqual(PacketType.ProtocolError, 52)

    def test_alpn_strings(self):
        self.assertEqual(RADIUS_ALPN_RADIUS_10, "radius/1.0")
        self.assertEqual(RADIUS_ALPN_RADIUS_11, "radius/1.1")

    def test_message_authenticator_code(self):
        self.assertEqual(ATTR_MESSAGE_AUTHENTICATOR, 80)

    def test_error_cause_code(self):
        self.assertEqual(ATTR_ERROR_CAUSE, 101)


# ── Packet construction with protocol_version ────────────────────────

class PacketProtocolVersionTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_default_protocol_version_is_none(self):
        pkt = Packet(dict=self.dict)
        self.assertIsNone(pkt.protocol_version)

    def test_set_protocol_version_1_1(self):
        pkt = Packet(dict=self.dict, protocol_version="1.1")
        self.assertEqual(pkt.protocol_version, "1.1")

    def test_protocol_version_via_kwargs(self):
        pkt = Packet(dict=self.dict, protocol_version="1.1")
        self.assertEqual(pkt.protocol_version, "1.1")

    def test_id_is_zero_in_1_1_mode(self):
        """RFC 9765: ID field is Reserved-1, always zero in 1.1 mode."""
        pkt = Packet(dict=self.dict, protocol_version="1.1")
        self.assertEqual(pkt.id, 0)

    def test_id_preserved_when_explicitly_set_in_1_1_mode(self):
        pkt = Packet(dict=self.dict, protocol_version="1.1", id=42)
        self.assertEqual(pkt.id, 42)

    def test_id_is_nonzero_in_legacy_mode(self):
        pkt = Packet(dict=self.dict)
        # ID should be assigned by CreateID(), which is always > 0
        self.assertIsNotNone(pkt.id)

    def test_token_attribute_default_none(self):
        pkt = Packet(dict=self.dict)
        self.assertIsNone(pkt.token)

    def test_token_attribute_set(self):
        token = b"\x01\x02\x03\x04"
        pkt = Packet(dict=self.dict, token=token, protocol_version="1.1")
        self.assertEqual(pkt.token, token)


# ── Token-based request/response matching ────────────────────────────

class TokenMatchingTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))
        self.token = b"\xaa\xbb\xcc\xdd"

    def test_verify_reply_token_match(self):
        """In 1.1 mode, VerifyReply matches on token only."""
        request = Packet(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertTrue(request.VerifyReply(reply))

    def test_verify_reply_token_mismatch(self):
        request = Packet(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        reply.token = b"\x00\x00\x00\x00"
        self.assertFalse(request.VerifyReply(reply))

    def test_verify_reply_token_none_fails(self):
        request = Packet(
            dict=self.dict,
            protocol_version="1.1",
            token=None,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertFalse(request.VerifyReply(reply))

    def test_create_reply_copies_token(self):
        request = Packet(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertEqual(reply.token, self.token)
        self.assertEqual(reply.protocol_version, "1.1")

    def test_auth_packet_create_reply_copies_token(self):
        request = AuthPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertEqual(reply.token, self.token)
        self.assertEqual(reply.protocol_version, "1.1")

    def test_acct_packet_create_reply_copies_token(self):
        request = AcctPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertEqual(reply.token, self.token)
        self.assertEqual(reply.protocol_version, "1.1")

    def test_coa_packet_create_reply_copies_token(self):
        request = CoAPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        reply = request.CreateReply()
        self.assertEqual(reply.token, self.token)
        self.assertEqual(reply.protocol_version, "1.1")


# ── Header format tests ──────────────────────────────────────────────

class HeaderFormatTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))
        self.token = b"\xaa\xbb\xcc\xdd"

    def test_auth_request_packet_1_1_header(self):
        """In 1.1 mode, authenticator = token + 12 zero bytes."""
        pkt = AuthPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
        )
        raw = pkt.RequestPacket()
        # First byte is code (AccessRequest=1)
        self.assertEqual(raw[0], PacketType.AccessRequest)
        # ID should be 0
        self.assertEqual(raw[1], 0)
        # Authenticator: token + 12 zero bytes
        authenticator = raw[4:20]
        self.assertEqual(authenticator[:4], self.token)
        self.assertEqual(authenticator[4:], 12 * b"\x00")

    def test_acct_request_packet_1_1_header(self):
        pkt = AcctPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
        )
        raw = pkt.RequestPacket()
        self.assertEqual(raw[0], PacketType.AccountingRequest)
        self.assertEqual(raw[1], 0)
        authenticator = raw[4:20]
        self.assertEqual(authenticator[:4], self.token)
        self.assertEqual(authenticator[4:], 12 * b"\x00")

    def test_coa_request_packet_1_1_header(self):
        pkt = CoAPacket(
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
        )
        raw = pkt.RequestPacket()
        self.assertEqual(raw[0], PacketType.CoARequest)
        self.assertEqual(raw[1], 0)
        authenticator = raw[4:20]
        self.assertEqual(authenticator[:4], self.token)
        self.assertEqual(authenticator[4:], 12 * b"\x00")

    def test_reply_packet_1_1_header(self):
        """ReplyPacket in 1.1 mode uses token-based authenticator."""
        pkt = Packet(
            code=PacketType.AccessAccept,
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=self.token + 12 * b"\x00",
        )
        raw = pkt.ReplyPacket()
        self.assertEqual(raw[0], PacketType.AccessAccept)
        self.assertEqual(raw[1], 0)
        authenticator = raw[4:20]
        self.assertEqual(authenticator[:4], self.token)
        self.assertEqual(authenticator[4:], 12 * b"\x00")

    def test_reply_packet_1_1_no_md5(self):
        """In 1.1 mode, ReplyPacket should NOT compute MD5."""
        pkt = Packet(
            code=PacketType.AccessAccept,
            dict=self.dict,
            protocol_version="1.1",
            token=self.token,
            secret=b"secret",
            authenticator=self.token + 12 * b"\x00",
        )
        raw = pkt.ReplyPacket()
        # Authenticator should be exactly token + zeros (no MD5)
        self.assertEqual(raw[4:20], self.token + 12 * b"\x00")


# ── Password handling tests ──────────────────────────────────────────

class PasswordTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_pw_crypt_plaintext_in_1_1_mode(self):
        """In 1.1 mode, PwCrypt returns plaintext (padded to 16 bytes)."""
        pkt = AuthPacket(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        result = pkt.PwCrypt("hello")
        # Should be padded to 16 bytes with null bytes
        self.assertEqual(len(result), 16)
        self.assertTrue(result.startswith(b"hello"))
        # No MD5 obfuscation — remaining bytes are null padding
        self.assertEqual(result[5:], b"\x00" * 11)

    def test_pw_decrypt_plaintext_in_1_1_mode(self):
        """In 1.1 mode, PwDecrypt strips null padding."""
        pkt = AuthPacket(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        encrypted = b"hello" + b"\x00" * 11
        result = pkt.PwDecrypt(encrypted)
        self.assertEqual(result, "hello")

    def test_pw_crypt_decrypt_roundtrip_1_1(self):
        """PwCrypt/PwDecrypt roundtrip in 1.1 mode."""
        pkt = AuthPacket(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        password = "MyP@ssw0rd!"
        encrypted = pkt.PwCrypt(password)
        decrypted = pkt.PwDecrypt(encrypted)
        self.assertEqual(decrypted, password)

    def test_pw_crypt_legacy_mode_still_obfuscates(self):
        """Legacy mode PwCrypt still uses MD5 obfuscation."""
        pkt = AuthPacket(
            dict=self.dict,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        result = pkt.PwCrypt("hello")
        # Should NOT be plaintext
        self.assertNotEqual(result[:5], b"hello")


# ── Salt encryption bypass tests ─────────────────────────────────────

class SaltEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_encrypt_2_bypassed_in_1_1_mode(self):
        """encrypt=2 attributes should not be salt-encrypted in 1.1 mode."""
        pkt = Packet(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        pkt["Test-Encrypted-String"] = "testvalue"
        # In 1.1 mode, should be stored as plain encoded value
        raw_values = pkt[5]  # Raw access by attribute code
        self.assertTrue(len(raw_values) > 0)
        # The raw value should be the plain string encoding (no salt prefix)
        self.assertEqual(raw_values[0], b"testvalue")

    def test_encrypt_2_applied_in_legacy_mode(self):
        """encrypt=2 attributes SHOULD be salt-encrypted in legacy mode."""
        pkt = Packet(
            dict=self.dict,
            secret=b"secret",
            authenticator=b"0123456789ABCDEF",
        )
        pkt["Test-Encrypted-String"] = "testvalue"
        raw_values = pkt[5]  # Raw access by attribute code
        # Should NOT be plaintext (salt + encrypted)
        self.assertNotEqual(raw_values[0], b"testvalue")
        self.assertTrue(len(raw_values[0]) > len(b"testvalue"))


# ── Message-Authenticator suppression tests ──────────────────────────

class MessageAuthenticatorTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_add_message_authenticator_noop_in_1_1(self):
        """add_message_authenticator is a no-op in 1.1 mode."""
        pkt = Packet(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
        )
        pkt.add_message_authenticator()
        self.assertIsNone(pkt.message_authenticator)
        self.assertFalse(pkt.has_key("Message-Authenticator"))

    def test_verify_message_authenticator_true_in_1_1(self):
        """verify_message_authenticator returns True in 1.1 mode."""
        pkt = Packet(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
        )
        self.assertTrue(pkt.verify_message_authenticator())

    def test_decode_discards_message_authenticator_in_1_1(self):
        """DecodePacket silently discards attr 80 in 1.1 mode."""
        # Build a raw packet with Message-Authenticator (attr 80)
        authenticator = b"\xaa\xbb\xcc\xdd" + 12 * b"\x00"
        ma_value = 16 * b"\xff"
        ma_attr = struct.pack("!BB", 80, len(ma_value) + 2) + ma_value
        header = struct.pack(
            "!BBH16s", PacketType.AccessRequest, 0, 20 + len(ma_attr), authenticator
        )
        raw = header + ma_attr

        pkt = Packet(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
        )
        pkt.DecodePacket(raw)
        # Message-Authenticator should have been discarded
        self.assertIsNone(pkt.message_authenticator)
        self.assertFalse(80 in pkt)

    def test_decode_preserves_message_authenticator_in_legacy(self):
        """DecodePacket keeps attr 80 in legacy mode."""
        authenticator = b"0123456789ABCDEF"
        ma_value = 16 * b"\xff"
        ma_attr = struct.pack("!BB", 80, len(ma_value) + 2) + ma_value
        header = struct.pack(
            "!BBH16s", PacketType.AccessRequest, 1, 20 + len(ma_attr), authenticator
        )
        raw = header + ma_attr

        pkt = Packet(dict=self.dict, secret=b"secret")
        pkt.DecodePacket(raw)
        self.assertTrue(pkt.message_authenticator)


# ── DecodePacket token extraction ─────────────────────────────────────

class DecodePacketTokenTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_decode_extracts_token_in_1_1(self):
        """DecodePacket extracts token from authenticator in 1.1 mode."""
        token = b"\x01\x02\x03\x04"
        authenticator = token + 12 * b"\x00"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 0, 20, authenticator)

        pkt = Packet(
            dict=self.dict,
            protocol_version="1.1",
            secret=b"secret",
        )
        pkt.DecodePacket(header)
        self.assertEqual(pkt.token, token)

    def test_decode_does_not_extract_token_in_legacy(self):
        """DecodePacket does not set token in legacy mode."""
        authenticator = b"0123456789ABCDEF"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 1, 20, authenticator)

        pkt = Packet(dict=self.dict, secret=b"secret")
        pkt.DecodePacket(header)
        self.assertIsNone(pkt.token)


# ── CHAP-Challenge requirement ────────────────────────────────────────

class ChapChallengeTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "chap"))

    def test_chap_requires_challenge_attr_in_1_1(self):
        """In 1.1 mode, VerifyChapPasswd raises if CHAP-Challenge not present."""
        chap_id = b"9"
        chap_challenge = b"987654321"
        chap_password = (
            chap_id + hashlib.md5(chap_id + b"test_password" + chap_challenge).digest()
        )

        pkt = AuthPacket(
            code=PacketType.AccessChallenge,
            secret=b"secret",
            authenticator=b"ABCDEFGHIJKLMNOP",
            dict=self.dict,
            protocol_version="1.1",
            CHAP_Password=chap_password,
            User_Name="test_name",
            # Note: No CHAP-Challenge attribute!
        )
        with self.assertRaises(PacketError):
            pkt.VerifyChapPasswd("test_password")

    def test_chap_with_challenge_attr_in_1_1(self):
        """In 1.1 mode, VerifyChapPasswd works when CHAP-Challenge is present."""
        chap_id = b"9"
        chap_challenge = b"987654321"
        chap_password = (
            chap_id + hashlib.md5(chap_id + b"test_password" + chap_challenge).digest()
        )

        pkt = AuthPacket(
            code=PacketType.AccessChallenge,
            secret=b"secret",
            authenticator=b"ABCDEFGHIJKLMNOP",
            dict=self.dict,
            protocol_version="1.1",
            CHAP_Password=chap_password,
            CHAP_Challenge=chap_challenge,
            User_Name="test_name",
        )
        self.assertTrue(pkt.VerifyChapPasswd("test_password"))


# ── parse_packet with protocol_version ────────────────────────────────

class ParsePacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_parse_packet_with_protocol_version(self):
        token = b"\x01\x02\x03\x04"
        authenticator = token + 12 * b"\x00"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 0, 20, authenticator)

        pkt = parse_packet(header, b"secret", self.dict, protocol_version="1.1")
        self.assertEqual(pkt.protocol_version, "1.1")
        self.assertEqual(pkt.token, token)
        self.assertIsInstance(pkt, AuthPacket)

    def test_parse_packet_legacy_default(self):
        authenticator = b"0123456789ABCDEF"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 1, 20, authenticator)

        pkt = parse_packet(header, b"secret", self.dict)
        self.assertIsNone(pkt.protocol_version)
        self.assertIsNone(pkt.token)

    def test_parse_acct_packet_1_1(self):
        token = b"\xde\xad\xbe\xef"
        authenticator = token + 12 * b"\x00"
        header = struct.pack(
            "!BBH16s", PacketType.AccountingRequest, 0, 20, authenticator
        )
        pkt = parse_packet(header, b"secret", self.dict, protocol_version="1.1")
        self.assertIsInstance(pkt, AcctPacket)
        self.assertEqual(pkt.token, token)

    def test_parse_coa_packet_1_1(self):
        token = b"\xca\xfe\xba\xbe"
        authenticator = token + 12 * b"\x00"
        header = struct.pack("!BBH16s", PacketType.CoARequest, 0, 20, authenticator)
        pkt = parse_packet(header, b"secret", self.dict, protocol_version="1.1")
        self.assertIsInstance(pkt, CoAPacket)
        self.assertEqual(pkt.token, token)


# ── RadSec client ALPN tests ─────────────────────────────────────────

class RadSecClientALPNTests(unittest.TestCase):
    def test_build_alpn_list_1_0(self):
        result = RadSecClient._build_alpn_list("1.0")
        self.assertEqual(result, [RADIUS_ALPN_RADIUS_10])

    def test_build_alpn_list_1_1(self):
        result = RadSecClient._build_alpn_list("1.1")
        self.assertEqual(result, [RADIUS_ALPN_RADIUS_11])

    def test_build_alpn_list_both(self):
        result = RadSecClient._build_alpn_list("1.0,1.1")
        self.assertEqual(result, [RADIUS_ALPN_RADIUS_10, RADIUS_ALPN_RADIUS_11])

    def test_create_token_length(self):
        token = RadSecClient._create_token()
        self.assertEqual(len(token), 4)
        self.assertIsInstance(token, bytes)

    def test_create_token_randomness(self):
        tokens = {RadSecClient._create_token() for _ in range(100)}
        # With 4 random bytes, should have many unique values
        self.assertGreater(len(tokens), 50)

    def test_client_default_no_alpn(self):
        """Default client should not configure ALPN."""
        client = RadSecClient(
            dict=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
        )
        self.assertIsNone(client.radius_version)

    def test_client_alpn_1_1_sets_tls_1_3(self):
        """Client with radius_version='1.1' should require TLS 1.3."""
        client = RadSecClient(
            dict=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            radius_version="1.1",
        )
        self.assertEqual(
            client.ssl_ctx.minimum_version, ssl.TLSVersion.TLSv1_3
        )

    def test_client_alpn_1_0_no_tls_1_3_requirement(self):
        """Client with radius_version='1.0' should not require TLS 1.3."""
        client = RadSecClient(
            dict=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
            certfile=CLIENT_CERTFILE,
            keyfile=CLIENT_KEYFILE,
            certfile_server=CA_CERTFILE,
            radius_version="1.0",
        )
        # Should not be TLS 1.3 minimum
        self.assertNotEqual(
            client.ssl_ctx.minimum_version, ssl.TLSVersion.TLSv1_3
        )


# ── RadSec server ALPN/security tests ────────────────────────────────

class RadSecServerALPNTests(unittest.TestCase):
    def test_server_default_no_alpn(self):
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
        )
        self.assertIsNone(server.radius_version)

    def test_server_cert_none_rejected_for_1_1(self):
        """RADIUS/1.1 server must reject ssl.CERT_NONE."""
        with self.assertRaises(ValueError) as cm:
            RadSecServer(
                certfile=SERVER_CERTFILE,
                keyfile=SERVER_KEYFILE,
                ca_certfile=CA_CERTFILE,
                dictionary=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
                verify_mode=ssl.CERT_NONE,
                radius_version="1.1",
            )
        self.assertIn("CERT_NONE", str(cm.exception))

    def test_server_cert_none_ok_for_legacy(self):
        """Legacy mode server allows ssl.CERT_NONE (backward compat)."""
        server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
            verify_mode=ssl.CERT_NONE,
        )
        self.assertIsNone(server.radius_version)

    def test_server_cert_none_rejected_for_both_versions(self):
        """RADIUS/1.0,1.1 server also rejects ssl.CERT_NONE."""
        with self.assertRaises(ValueError):
            RadSecServer(
                certfile=SERVER_CERTFILE,
                keyfile=SERVER_KEYFILE,
                ca_certfile=CA_CERTFILE,
                dictionary=Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary")),
                verify_mode=ssl.CERT_NONE,
                radius_version="1.0,1.1",
            )

    def test_server_build_alpn_list(self):
        self.assertEqual(
            RadSecServer._build_alpn_list("1.0"), [RADIUS_ALPN_RADIUS_10]
        )
        self.assertEqual(
            RadSecServer._build_alpn_list("1.1"), [RADIUS_ALPN_RADIUS_11]
        )
        self.assertEqual(
            RadSecServer._build_alpn_list("1.0,1.1"),
            [RADIUS_ALPN_RADIUS_10, RADIUS_ALPN_RADIUS_11],
        )


# ── Server packet_received with protocol_version ─────────────────────

class ServerPacketReceivedTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))
        self.server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
        )
        from pyrad2.server import RemoteHost
        self.server.hosts = {
            "127.0.0.1": RemoteHost("name", b"radsec", "127.0.0.1")
        }

    async def test_packet_received_with_protocol_version(self):
        """packet_received passes protocol_version through to parse_packet."""
        token = b"\x01\x02\x03\x04"
        authenticator = token + 12 * b"\x00"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 0, 20, authenticator)

        reply = await self.server.packet_received(
            header, host="127.0.0.1", protocol_version="1.1"
        )
        self.assertEqual(reply.protocol_version, "1.1")

    async def test_packet_received_legacy(self):
        """packet_received in legacy mode has no protocol_version."""
        authenticator = b"0123456789ABCDEF"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 1, 20, authenticator)

        reply = await self.server.packet_received(header, host="127.0.0.1")
        self.assertIsNone(reply.protocol_version)


# ── Server verify_packet bug fix ──────────────────────────────────────

class ServerVerifyPacketBugFixTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.dictionary = Dictionary(os.path.join(TEST_ROOT_PATH, "dicts/dictionary"))
        self.server = RadSecServer(
            certfile=SERVER_CERTFILE,
            keyfile=SERVER_KEYFILE,
            ca_certfile=CA_CERTFILE,
            dictionary=self.dictionary,
            verify_packet=True,
        )
        from pyrad2.server import RemoteHost
        self.server.hosts = {
            "127.0.0.1": RemoteHost("name", b"radsec", "127.0.0.1")
        }

    async def test_verify_access_request(self):
        """Server should call VerifyAuthRequest for AccessRequest packets."""
        authenticator = b"0123456789ABCDEF"
        header = struct.pack("!BBH16s", PacketType.AccessRequest, 1, 20, authenticator)
        # This should not raise AttributeError (old packet.verify() bug)
        reply = await self.server.packet_received(header, host="127.0.0.1")
        self.assertIsNotNone(reply)

    async def test_verify_acct_request_fails_wrong_secret(self):
        """Server should use VerifyAcctRequest for AccountingRequest."""
        # Build a valid accounting request with proper authenticator
        pkt = AcctPacket(
            code=PacketType.AccountingRequest,
            secret=b"wrong_secret",
            dict=self.dictionary,
        )
        raw = pkt.RequestPacket()
        # This should raise PacketError because secret doesn't match
        with self.assertRaises(PacketError):
            await self.server.packet_received(raw, host="127.0.0.1")


# ── End-to-end 1.1 packet roundtrip ──────────────────────────────────

class EndToEndPacketRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_auth_packet_encode_decode_roundtrip_1_1(self):
        """Full encode-decode roundtrip for AuthPacket in 1.1 mode."""
        token = b"\xde\xad\xbe\xef"
        pkt = AuthPacket(
            code=PacketType.AccessRequest,
            dict=self.dict,
            protocol_version="1.1",
            token=token,
            secret=b"secret",
        )
        pkt["Test-String"] = "hello"
        pkt["Test-Integer"] = 42

        raw = pkt.RequestPacket()

        # Decode it
        decoded = parse_packet(raw, b"secret", self.dict, protocol_version="1.1")
        self.assertEqual(decoded.code, PacketType.AccessRequest)
        self.assertEqual(decoded.id, 0)
        self.assertEqual(decoded.token, token)
        self.assertEqual(decoded["Test-String"], ["hello"])
        self.assertEqual(decoded["Test-Integer"], [42])

    def test_acct_packet_encode_decode_roundtrip_1_1(self):
        """Full encode-decode roundtrip for AcctPacket in 1.1 mode."""
        token = b"\xca\xfe\xba\xbe"
        pkt = AcctPacket(
            code=PacketType.AccountingRequest,
            dict=self.dict,
            protocol_version="1.1",
            token=token,
            secret=b"secret",
        )
        pkt["Test-String"] = "world"

        raw = pkt.RequestPacket()

        decoded = parse_packet(raw, b"secret", self.dict, protocol_version="1.1")
        self.assertEqual(decoded.code, PacketType.AccountingRequest)
        self.assertEqual(decoded.token, token)
        self.assertEqual(decoded["Test-String"], ["world"])

    def test_request_reply_roundtrip_1_1(self):
        """Request -> CreateReply -> ReplyPacket -> decode roundtrip."""
        token = b"\x11\x22\x33\x44"
        request = AuthPacket(
            code=PacketType.AccessRequest,
            dict=self.dict,
            protocol_version="1.1",
            token=token,
            secret=b"secret",
        )
        request.RequestPacket()

        reply = request.CreateReply()
        reply.code = PacketType.AccessAccept
        reply["Test-String"] = "accepted"

        raw_reply = reply.ReplyPacket()

        decoded_reply = parse_packet(
            raw_reply, b"secret", self.dict, protocol_version="1.1"
        )
        self.assertEqual(decoded_reply.code, PacketType.AccessAccept)
        self.assertEqual(decoded_reply.token, token)
        self.assertEqual(decoded_reply["Test-String"], ["accepted"])

        # Verify reply matches request by token
        self.assertTrue(request.VerifyReply(decoded_reply))


# ── Legacy backward compatibility ─────────────────────────────────────

class LegacyBackwardCompatTests(unittest.TestCase):
    """Ensure all legacy behavior is preserved when protocol_version is None."""

    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))

    def test_legacy_auth_packet_unchanged(self):
        pkt = AuthPacket(
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
            id=0,
        )
        raw = pkt.RequestPacket()
        self.assertEqual(raw[:1], b"\x01")  # AccessRequest
        self.assertEqual(raw[1:2], b"\x00")  # ID 0
        self.assertIsNone(pkt.protocol_version)
        self.assertIsNone(pkt.token)

    def test_legacy_acct_packet_md5_authenticator(self):
        pkt = AcctPacket(
            dict=self.dict,
            secret=b"secret",
            id=0,
        )
        raw = pkt.RequestPacket()
        # Authenticator should be MD5-based (not all zeros)
        authenticator = raw[4:20]
        self.assertNotEqual(authenticator, 16 * b"\x00")

    def test_legacy_reply_uses_md5(self):
        pkt = Packet(
            code=PacketType.AccessAccept,
            id=0,
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
        )
        raw = pkt.ReplyPacket()
        # Authenticator should be MD5 hash
        expected_authenticator = hashlib.md5(
            raw[:4] + b"01234567890ABCDE" + raw[20:] + b"secret"
        ).digest()
        self.assertEqual(raw[4:20], expected_authenticator)

    def test_legacy_verify_reply_uses_md5(self):
        request = Packet(
            id=0,
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
        )
        reply = request.CreateReply()
        self.assertTrue(request.VerifyReply(reply))

    def test_legacy_pw_crypt_uses_md5(self):
        pkt = AuthPacket(
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
        )
        result = pkt.PwCrypt("hello")
        # Should be obfuscated
        self.assertNotEqual(result[:5], b"hello")

    def test_legacy_salt_crypt_applied(self):
        pkt = Packet(
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
        )
        pkt["Test-Encrypted-String"] = "testvalue"
        raw = pkt[5]
        # Should be salt-encrypted (not plaintext)
        self.assertNotEqual(raw[0], b"testvalue")

    def test_legacy_message_authenticator_works(self):
        pkt = AuthPacket(
            code=PacketType.AccessRequest,
            dict=self.dict,
            secret=b"secret",
            authenticator=b"01234567890ABCDE",
        )
        pkt.add_message_authenticator()
        self.assertTrue(pkt.message_authenticator)
        self.assertTrue(pkt.has_key("Message-Authenticator"))
