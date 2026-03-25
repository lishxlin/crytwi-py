import ctypes


class CrytwiFixedMetaHeader(ctypes.LittleEndianStructure):
	_pack_ = 1  # Corresponds to C-style packed structures, no padding.
	_fields_ = [
		# ------------------------------------
		# Housekeeping
		# ------------------------------------
		("magic_byte",            ctypes.c_uint8),
		("signature",             ctypes.c_uint8 * 6),
		("endian_flag",           ctypes.c_uint8),
		("version",               ctypes.c_uint8),
		("flags",                 ctypes.c_uint8),  # 0x00 = Isolated, 0x01 = Managed. This parameter has an alternate name, "mode"

		# ------------------------------------
		# KDF Seeds
		# ------------------------------------
		("cipher_type",           ctypes.c_uint8),
		("master_salt",           ctypes.c_uint64 * 4),
		("master_iv_seed",        ctypes.c_uint64),  # !!Combine counter , random value and sha256!!
		("random_value",          ctypes.c_uint64),

		# ------------------------------------
		# Argon2id KDF Parameters
		# ------------------------------------
		("argon2_t",              ctypes.c_uint8),    # 1B: Time Cost (t)
		("argon2_p",              ctypes.c_uint8),    # 1B: Parallelism (p)
		("argon2_c",          ctypes.c_uint16),   # 2B: Memory Cost in kibibytes

		# ------------------------------------
		# Scrypt KDF Parameters
		# ------------------------------------
		("scrypt_n",              ctypes.c_uint16),   # 2B: N Cost
		("scrypt_r",              ctypes.c_uint8),    # 1B: r Cost
		("scrypt_p",              ctypes.c_uint8),    # 1B: p Cost

		# ------------------------------------
		# File Information
		# ------------------------------------
		("posix_timestamp",       ctypes.c_uint64),
		("max_single_chunk_size", ctypes.c_uint32),  # Won't insert 0 when last chunk generate.
		("payload_len",           ctypes.c_uint8 * 5)  # RAW Payload size in bytes.
	]


class CrytwiDynamicMetaHeader(ctypes.LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
		("encrypted_alias_len", ctypes.c_uint16),
		("encrypted_filename_len", ctypes.c_uint16)
	]


META_FIXED_HEADER_SIZE = ctypes.sizeof(CrytwiFixedMetaHeader)
META_DYNAMIC_HEADER_SIZE = ctypes.sizeof(CrytwiDynamicMetaHeader)


class CrytwiFixedChunkStruct(ctypes.LittleEndianStructure):
	_pack_ = 1  # Corresponds to C-style packed structures, no padding.
	_fields_ = [
		("seq", ctypes.c_uint8 * 3),
		("fin", ctypes.c_uint8),
		("encrypted_payload_size", ctypes.c_uint32)
	]


CHUNK_FIXED_HEADER_SIZE = ctypes.sizeof(CrytwiFixedChunkStruct)  # Current is 8 bytes.
