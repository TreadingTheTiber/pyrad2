# Packet codes
from enum import IntEnum


class PacketType(IntEnum):
    AccessRequest = 1
    AccessAccept = 2
    AccessReject = 3
    AccountingRequest = 4
    AccountingResponse = 5
    AccessChallenge = 11
    StatusServer = 12
    StatusClient = 13
    DisconnectRequest = 40
    DisconnectACK = 41
    DisconnectNAK = 42
    CoARequest = 43
    CoAACK = 44
    CoANAK = 45
    ProtocolError = 52  # RFC 7930 §4


# RADIUS/1.1 protocol version constants (RFC 9765)
RADIUS_ALPN_RADIUS_10 = "radius/1.0"
RADIUS_ALPN_RADIUS_11 = "radius/1.1"

# Message-Authenticator attribute code
ATTR_MESSAGE_AUTHENTICATOR = 80

# Error-Cause attribute code (RFC 5765)
ATTR_ERROR_CAUSE = 101


class EAPPacketType(IntEnum):
    REQUEST = 1
    RESPONSE = 2


class EAPType(IntEnum):
    IDENTITY = 1


DATATYPES = frozenset(
    [
        "string",
        "ipaddr",
        "integer",
        "date",
        "octets",
        "abinary",
        "ipv6addr",
        "ipv6prefix",
        "short",
        "byte",
        "signed",
        "ifid",
        "ether",
        "tlv",
        "integer64",
    ]
)
