import os
import gc
import ctypes
import errno
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from .misc_utils import get_uint_max
from .security import burn_mem


def init_kdf_params(
	at: int = 3,
	ap: int = 1,
	ac: int = 0xFFFF,
	sn: int = 16384,
	sr: int = 8,
	sp: int = 1
) -> tuple | int:
	U8_MAX = get_uint_max(ctypes.c_uint8)
	U16_MAX = get_uint_max(ctypes.c_uint16)

	if not (0 <= at <= U8_MAX):
		print(f"Argon2id t_cost ({at}) exceeds {ctypes.c_uint8.__name__} range")
		return errno.EINVAL
	if not (0 <= ap <= U8_MAX):
		print(f"Argon2id p_parallel ({ap}) exceeds {ctypes.c_uint8.__name__} range")
		return errno.EINVAL
	if not (0 <= ac <= U16_MAX):
		print(f"Argon2id cost(kibibytes) ({ac}) exceeds {ctypes.c_uint16.__name__} range")
		return errno.EINVAL
	if not (0 <= sn <= U16_MAX):
		print(f"Scrypt N cost ({sn}) exceeds {ctypes.c_uint16.__name__} range")
		return errno.EINVAL
	if not (0 <= sr <= U8_MAX):
		print(f"Scrypt r cost ({sr}) exceeds {ctypes.c_uint8.__name__} range")
		return errno.EINVAL
	if not (0 <= sp <= U8_MAX):
		print(f"Scrypt p cost ({sp}) exceeds {ctypes.c_uint8.__name__} range")
		return errno.EINVAL

	return (at, ap, ac, sn, sr, sp)


def generate_header_entropy() -> tuple[bytes, bytes, bytes]:
	salt = os.urandom(ctypes.sizeof(ctypes.c_uint64 * 4))
	iv_seed = os.urandom(ctypes.sizeof(ctypes.c_uint64))
	r_val = os.urandom(ctypes.sizeof(ctypes.c_uint64))

	return (salt, iv_seed, r_val)


def derive_kdf_material(
	pwd_buf: bytearray,
	entropies: tuple,
	kdf_params: tuple
) -> Tuple[bytearray, bytearray]:
	try:
		# Scrypt KDF is used for metadata only
		sKDF = Scrypt(
			length=ctypes.sizeof(ctypes.c_uint64 * 4),
			salt = entropies[0],
			n = kdf_params[3],
			r = kdf_params[4],
			p = kdf_params[5]
		).derive(pwd_buf)

		# Argon2id KDF is used for payload only
		aKDF = Argon2id(
			salt = entropies[0],
			length = 32,
			iterations = kdf_params[0],
			lanes = kdf_params[1],
			memory_cost = kdf_params[2],
			secret = entropies[2]
		).derive(pwd_buf)

		return bytearray(sKDF), bytearray(aKDF)
	finally:
		burn_mem(pwd_buf)
		del pwd_buf
		gc.collect()


def derive_chunk_iv(
	iv_seed: bytes,
	seq: int,
	r_val: bytes
) -> bytes:
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(iv_seed)
	digest.update(seq.to_bytes(3, 'little'))
	digest.update(r_val)

	return digest.finalize()[:12]


def vla_decryptor(
	manage_flag: int = 0x00,
	vla_ciphers: tuple = (),
	kdf_key: bytes = b'',
	iv_seed: bytes = b''
) -> tuple | int:
	if manage_flag == 0x00:
		return ()

	alias_cipher, fname_cipher = vla_ciphers
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

	alias_de = Cipher(
		algorithms.AES(kdf_key),
		modes.GCM(iv_alias),
		backend=default_backend()
	).decryptor()

	fname_de = Cipher(
		algorithms.AES(kdf_key),
		modes.GCM(iv_filename),
		backend=default_backend()
	).decryptor()

	return (
		alias_de.update(alias_cipher).decode('utf-8'),
		fname_de.update(fname_cipher).decode('utf-8')
	)


def chunk_encryptor(
	raw_data: bytes,
	seq: int,
	key: bytes,
	iv: bytes
) -> bytes:
	print(f"[*] Going to encrypt chunk, id {seq}")
	encryptor = Cipher(
		algorithms.AES(key),
		modes.GCM(iv)
	).encryptor()

	ciphertext = encryptor.update(raw_data) + encryptor.finalize()
	blob = ciphertext + encryptor.tag

	return blob


def chunk_decryptor(
	p_bytes: bytes,
	key: bytes,
	iv: bytes,
	tag: bytes,
	chunk_seq: int,
	mode: int = 0
) -> bytes:
	print(f"[*] Decrypting chunk {chunk_seq}")

	decryptor = Cipher(
		algorithms.AES(key),
		modes.GCM(iv, tag)
	).decryptor()

	return decryptor.update(p_bytes) + decryptor.finalize()


def chunk_validator(
	pt_bytes: bytes,
	key: bytes,
	iv: bytes,
	chunk_seq: int,
	mode: int = 0
) -> int:
	print(f"[*] Validating chunk integrity, id {chunk_seq} (mode: {mode})")

	try:
		tag = pt_bytes[-16:]
		ciphertext = pt_bytes[:-16]

		decryptor = Cipher(
			algorithms.AES(key),
			modes.GCM(iv, tag)
		).decryptor()

		decryptor.update(ciphertext)
		decryptor.finalize()

		return 0
	except Exception as e:
		print(f"[!] Integrity check FAILED for chunk {chunk_seq}: {e}")
		return errno.EBADMSG
# WE NEED USE ERRNO
