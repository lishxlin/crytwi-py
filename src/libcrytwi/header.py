import ctypes
import time
import errno
from typing import BinaryIO, Tuple
from .structs import CrytwiFixedMetaHeader, CrytwiDynamicMetaHeader, META_DYNAMIC_HEADER_SIZE, META_FIXED_HEADER_SIZE
from .constants import MAGICNUM, FORMAT_VERSION, SIGNATURE
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def assemble_fixed_meta_header(
	manage_flag: int = 0x00,
	cipher_type: int = 0x00,
	endian_flag: int = 0x00,
	entropies: tuple = (),
	kdf_params: tuple = (),
	max_chunk_size: int = (64 * 1024),
	payload_len: int = 0
) -> bytes:
	if endian_flag == 0x00:
		endian = 'little'
	elif endian_flag == 0x01:
		endian = 'big'
	else:
		print(f"[!] Endian {endian} not supported!")
		return errno.EPROTOTYPE
	# Prepare fixed meta header structure
	fixed_header = CrytwiFixedMetaHeader()

	fixed_header.magic_byte = MAGICNUM
	fixed_header.signature = (ctypes.c_uint8 * 6)(*SIGNATURE)
	fixed_header.endian_flag = endian_flag
	fixed_header.version = FORMAT_VERSION
	fixed_header.flags = manage_flag  # Isolated
	fixed_header.cipher_type = cipher_type  # AES, for example
	ctypes.memmove(fixed_header.master_salt, entropies[0], ctypes.sizeof(ctypes.c_uint64 * 4))
	fixed_header.master_iv_seed = (ctypes.c_uint64).from_buffer_copy(entropies[1])  # Store IV from stage 'Key Generation'
	fixed_header.random_value = (ctypes.c_uint64).from_buffer_copy(entropies[2])
	fixed_header.argon2_t = kdf_params[0]
	fixed_header.argon2_p = kdf_params[1]
	fixed_header.argon2_c = kdf_params[2]
	fixed_header.scrypt_n = kdf_params[3]
	fixed_header.scrypt_r = kdf_params[4]
	fixed_header.scrypt_p = kdf_params[5]
	fixed_header.posix_timestamp = (ctypes.c_uint64)((int(time.time())))
	fixed_header.max_single_chunk_size = (ctypes.c_uint32)(int(max_chunk_size * ctypes.sizeof(ctypes.c_uint8)))
	fixed_header.payload_len[:] = payload_len.to_bytes(ctypes.sizeof(ctypes.c_uint8 * 5), endian)

	return bytes(fixed_header)


def assemble_dynamic_meta_header(
	manage_flag: int = 0x00,
	non_encrypt_meta_infos: tuple = (),
	kdf_key: bytes = b'',
	iv_seed: bytes = b'',
) -> bytes:
	if manage_flag == 0x00:
		return bytes()

	alias_str, filename_str = non_encrypt_meta_infos
	iv_alias = HKDF(
		algorithm=hashes.SHA256(),
		length=12,
		salt=iv_seed,
		info=b"crytwi-alias-iv",
		backend=default_backend()
	).derive(kdf_key)

	iv_filename = HKDF(
		algorithm=hashes.SHA256(),
		length=12,
		salt=iv_seed,
		info=b"crytwi-filename-iv",
		backend=default_backend()
	).derive(kdf_key)

	cipher_alias = Cipher(algorithms.AES(kdf_key), modes.GCM(iv_alias), backend=default_backend()).encryptor()
	cipher_file = Cipher(algorithms.AES(kdf_key), modes.GCM(iv_filename), backend=default_backend()).encryptor()

	alias_blob = cipher_alias.update(alias_str.encode('utf-8')) + cipher_alias.finalize()
	filename_blob = cipher_file.update(filename_str.encode('utf-8')) + cipher_file.finalize()

	dynamic_struct = CrytwiDynamicMetaHeader()
	dynamic_struct.encrypted_alias_len = len(alias_blob)
	dynamic_struct.encrypted_filename_len = len(filename_blob)

	return bytes(dynamic_struct) + alias_blob + filename_blob


def extract_meta_header(
	file: BinaryIO,
	offset: int = 0
) -> CrytwiFixedMetaHeader | int:
	fixed_size = META_FIXED_HEADER_SIZE

	file.seek(offset)
	raw_bytes = file.read(fixed_size)

	if len(raw_bytes) < fixed_size:
		print(f"Header truncated: expected {fixed_size}")
		return errno.EIO

	header_obj = CrytwiFixedMetaHeader.from_buffer_copy(raw_bytes)

	return header_obj


def format_compat(
	ver: int
) -> int:
	if ver == FORMAT_VERSION:
		return 0
	if ver > FORMAT_VERSION:
		print(f"[!] Version too high:  File has {ver}")
		return errno.EPROTONOSUPPORT
	# compat_helper() FUTURE UPDATE
	return 0


def dy_vla_cipher(
	mode: int,
	file: BinaryIO,
	offset: int  # the Dynamic Meta header start
) -> Tuple | int:
	# NOTES: Here we only dump VLA data, not header itself.
	if mode != 0x01:
		return ()

	file.seek(offset)
	dymeta_bytes = file.read(META_DYNAMIC_HEADER_SIZE)
	dymeta = CrytwiDynamicMetaHeader.from_buffer_copy(dymeta_bytes)
	ealias_len = dymeta.encrypted_alias_len
	efilename_len = dymeta.encrypted_filename_len
	alias_cipher = file.read(ealias_len)
	filename_cipher = file.read(efilename_len)

	return (alias_cipher, filename_cipher)
