# NOTICE: some constants are located in ./structs.py


MAGICNUM = 0x9F
SIGNATURE = b"CRYTWI"
PROBE_SIZE = 7
ENDIAN = 0x00
FORMAT_VERSION = 0x01
CHIPHER_TYPE = 0x00
DEBUG_FLAG = True

TOTAL_TRAILER_READ_SIZE = 10  # With extra 2 bytes -- \x00\x01'
GCM_TAG_SIZE = 16

# Trailer pattern for quick validation
TRAILER_PATTERN_7B = b'\x02\x00\x00\x00\x00\x00\x0A'
CHUNK0_PATTERN_4B_NON_FINAL = b'\x00\x00\x00\x00'
CHUNK0_PATTERN_4B_FINAL = b'\x00\x00\x00\x01'
