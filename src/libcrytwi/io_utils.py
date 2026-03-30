import os
import ctypes
import errno
from typing import BinaryIO, List, Dict
from .structs import CrytwiFixedChunkStruct
from .constants import TOTAL_TRAILER_READ_SIZE, CHUNK0_PATTERN_4B_FINAL, CHUNK0_PATTERN_4B_NON_FINAL
from .constants import TRAILER_PATTERN_7B
from .constants import PROBE_SIZE, MAGICNUM, SIGNATURE, GCM_TAG_SIZE
from .structs import CHUNK_FIXED_HEADER_SIZE


def early_io_loader(
	file: BinaryIO,
	offset: int = 0
) -> int:
	try:
		file.seek(offset)
		raw_probe = file.read(PROBE_SIZE)

		if len(raw_probe) < (PROBE_SIZE):
			return errno.ENOEXEC
		if raw_probe[0] != MAGICNUM or raw_probe[1:7] != SIGNATURE:
			print(f"[!] Signature Mismatch: Expected {hex(MAGICNUM)} {SIGNATURE}, got {raw_probe.hex()}")
			return errno.ENOEXEC

		return 0
	except Exception as e:
		print(f"[!] IO Error during early probe: {e}")
		return errno.EIO


def compute_processor_map(
	file_raw_size: int,
	max_chunk_size_kb: int = 64,
	start_seq: int = 0
) -> List[Dict[int, int]]:
	processor_map = []
	if file_raw_size <= 0:
		return processor_map
	current_offset = 0
	remaining_data = 0
	max_chunk_size_bytes = max_chunk_size_kb * 1024

	total_data_chunks = int(file_raw_size // max_chunk_size_bytes)
	remaining_data = int(file_raw_size % max_chunk_size_bytes)

	if total_data_chunks == 0:
		return [{0: 0}]

	for seq in range(start_seq, total_data_chunks):
		processor_map.append({seq: current_offset})
		current_offset += max_chunk_size_bytes

	if remaining_data > 0:
		processor_map.append({total_data_chunks: current_offset})

	return processor_map


def file_splitter(
	file: BinaryIO,
	offset: int,  # Offset is the position that seek to.
	length_kb: int = 64
) -> bytes | int:
	try:
		file.seek(offset)
		data = file.read(int(length_kb * 1024))
		return data
	except Exception:
		print("[!] We encountered in I/O Problem!")
		return errno.EIO


def generate_chunk(
	data: bytes,  # payload + tag
	seq: int,
	endian: int = 0x00,
	final_flag: int = 0x00,
	non_tag_length: int = (64 * 1024)
) -> bytes | int:
	chunk_header = CrytwiFixedChunkStruct()

	if endian == 0x00:
		endian_flag = 'little'
	elif endian == 0x01:
		endian_flag = 'big'
	else:
		print(f"[!] Endian {endian} not supported!")
		return errno.EPROTOTYPE
	chunk_header.seq[:] = (seq).to_bytes(3, endian_flag)

	chunk_header.fin = final_flag
	chunk_header.encrypted_payload_size = (ctypes.c_uint32)(int(non_tag_length * ctypes.sizeof(ctypes.c_uint8)))

	if (int(len(data) - GCM_TAG_SIZE)) != int(non_tag_length * ctypes.sizeof(ctypes.c_uint8)):
		print(f"[!] Get {int(len(data))}, wants {int(non_tag_length * ctypes.sizeof(ctypes.c_uint8) + GCM_TAG_SIZE)}")
		return errno.EINVAL

	return bytes(chunk_header) + data


def build_trailer(
	total_seq: int
) -> bytes:
	chunk_header = CrytwiFixedChunkStruct()

	chunk_header.seq[:] = (total_seq).to_bytes(3, 'little')
	chunk_header.fin = 0x02
	chunk_header.encrypted_payload_size = 0x00
	header_bytes = bytes(chunk_header)
	trailer_sign = b'\x00\x0A'

	return header_bytes + trailer_sign


def init_merger():
	expected_seq = 0

	def merger(
		target_file: BinaryIO,
		data: bytes,
		incoming_seq: int,
	):
		nonlocal expected_seq
		print(f"[*] I am processing {incoming_seq}, I hope next chunk is {incoming_seq + 1}")
		if incoming_seq != expected_seq:
			print(f"[!] Expected {expected_seq}, got {incoming_seq}")
			return errno.EINVAL
		target_file.write(data)
		expected_seq += 1

	return merger
# Note: MT-unsafe in current design! Use it in ST only.
# A MT-safe merger PoC will be implemented in C.


def chunks_format_checker(
	p_chunks_h: BinaryIO,
	p_chunks_ofs: int,
	format_ver: int
) -> int:
	p_chunks_h.seek(0, os.SEEK_END)
	data_chunks_size = p_chunks_h.tell() - p_chunks_ofs
	p_chunks_h.seek(p_chunks_ofs)  # seek back to payload chunks start
	if data_chunks_size < TOTAL_TRAILER_READ_SIZE:
		print("[!] FAILURE: Chunks region too small to contain a full 10-byte trailer.")
		print("[!] Data chunks truncated")
		return errno.EBADMSG
	if data_chunks_size < (CHUNK_FIXED_HEADER_SIZE + TOTAL_TRAILER_READ_SIZE):
		print("[@] Warning: Payload chunks region contains no data chunks.")

	headchunk_bytes = p_chunks_h.read(CHUNK_FIXED_HEADER_SIZE)
	if len(headchunk_bytes) < CHUNK_FIXED_HEADER_SIZE:
		print("[!] Incomplete Chunk 0 Header.")
		return errno.EBADMSG

	first_4_bytes = headchunk_bytes[:4]
	if not ((first_4_bytes == CHUNK0_PATTERN_4B_NON_FINAL) or (first_4_bytes == CHUNK0_PATTERN_4B_FINAL)):
		print("[!] Pattern Error when reading head chunk.")
		return errno.EILSEQ

	p_chunks_h.seek(-(TOTAL_TRAILER_READ_SIZE - ctypes.sizeof(ctypes.c_uint8) * 3), os.SEEK_END)
	trailer_bytes = p_chunks_h.read((TOTAL_TRAILER_READ_SIZE - ctypes.sizeof(ctypes.c_uint8) * 3))
	if trailer_bytes != TRAILER_PATTERN_7B:
		print(f"[*] Read: {trailer_bytes}")
		print("[!] Trailer validation failed. Bytes read do not match the expected pattern.")
		return errno.EILSEQ

	p_chunks_h.seek(p_chunks_ofs)
	return 0


def prep_chunk_extract(
	p_chunk_h: BinaryIO,
	p_chunk_ofs: int,
	expected_seq: int,
	format_ver: int
) -> int:
	p_chunk_h.seek(p_chunk_ofs)
	chunk_header_bytes = p_chunk_h.read(CHUNK_FIXED_HEADER_SIZE)
	header = CrytwiFixedChunkStruct.from_buffer_copy(chunk_header_bytes)
	actual_seq = int.from_bytes(header.seq, "little")
	fin_flag = header.fin
	if actual_seq != expected_seq:
		print(f"[!] Sequence mismatch: Expected {expected_seq}, got {actual_seq}")
		return -errno.EBADMSG
	if fin_flag == 0x02:
		print("[*] Special flag 0x02 detected.")
		return -1

	return header.encrypted_payload_size
