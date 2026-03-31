import libcrytwi
import ctypes
import os
import errno


enc_f = open("parts-tests-files/single-py.test", "rb")
out_f = open("parts-tests-files/crafted.png", "wb")

try:
	early_ret = libcrytwi.early_io_loader(enc_f)
	if early_ret != 0:
		raise Exception(early_ret)

	header_obj = libcrytwi.extract_meta_header(
		enc_f
	)
	if header_obj == errno.EIO:
		raise Exception(header_obj)
	if header_obj.endian_flag == 0x00:
		print("[*] Little Endian")
		endian_flag = header_obj.endian_flag
		endian = "little"
	if header_obj.flags != 0x00:
		print("[*] Only process isolated file.")
		raise Exception(errno.EINVAL)
	ori_payload_len = int.from_bytes(bytes(header_obj.payload_len), 'little')
	print(f"[*] Payload size is {ori_payload_len}.")
	max_single_chunk_size = header_obj.max_single_chunk_size
	print(f"[*] Max chunk size is {max_single_chunk_size} per chunk.")
	print(f"[*] File created at POSIX timestamp: {header_obj.posix_timestamp}.")

	kdf_params = libcrytwi.init_kdf_params(
		header_obj.argon2_t,
		header_obj.argon2_p,
		header_obj.argon2_c,
		header_obj.scrypt_n,
		header_obj.scrypt_r,
		header_obj.scrypt_p
	)
	if kdf_params == errno.EINVAL:
		raise Exception(kdf_params)

	keys = libcrytwi.derive_kdf_material(
		libcrytwi.get_pass(),
		entropies=(
			bytes(header_obj.master_salt),
			header_obj.master_iv_seed.to_bytes(
				ctypes.sizeof(ctypes.c_uint64),
				endian
			),
			header_obj.random_value.to_bytes(
				ctypes.sizeof(ctypes.c_uint64),
				endian
			)
		),
		kdf_params=kdf_params
	)
	print(f"[*] My offset is {enc_f.tell()} now.")
	csfc_ret = libcrytwi.chunks_format_checker(
		enc_f,
		enc_f.tell(),
		header_obj.version
	)
	if csfc_ret != 0:
		raise Exception(csfc_ret)

	# Only validate chunk now
	seq = 0
	ofs = enc_f.tell()
	chunks_start_ofs = ofs
	while True:
		psize = libcrytwi.prep_chunk_extract(
			enc_f,
			ofs,
			seq,
			header_obj.version
		)
		if psize == -1:
			break
		elif psize == -errno.EBADMSG:
			raise Exception(psize)

		pt_bytes = enc_f.read(psize + libcrytwi.constants.GCM_TAG_SIZE)
		vali_ret = libcrytwi.chunk_validator(
			pt_bytes,
			keys[1],
			libcrytwi.derive_chunk_iv(
				header_obj.master_iv_seed.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				),
				seq,
				header_obj.random_value.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				)
			),
			seq,
			header_obj.flags
		)
		if vali_ret != 0:
			raise Exception(vali_ret)
		ofs = enc_f.tell()
		seq += 1

	merger = libcrytwi.init_merger()

	# Validate again, but follow decryption
	seq = 0
	ofs = chunks_start_ofs
	while True:
		psize = libcrytwi.prep_chunk_extract(
			enc_f,
			ofs,
			seq,
			header_obj.version
		)
		if psize == -1:
			break
		elif psize == -errno.EBADMSG:
			raise Exception(psize)

		pt_bytes = enc_f.read(psize + libcrytwi.constants.GCM_TAG_SIZE)
		vali_ret = libcrytwi.chunk_validator(
			pt_bytes,
			keys[1],
			libcrytwi.derive_chunk_iv(
				header_obj.master_iv_seed.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				),
				seq,
				header_obj.random_value.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				)
			),
			seq,
			header_obj.flags
		)
		if vali_ret != 0:
			raise Exception(vali_ret)
		d_bytes = libcrytwi.chunk_decryptor(
			pt_bytes[:-libcrytwi.constants.GCM_TAG_SIZE],
			keys[1],
			libcrytwi.derive_chunk_iv(
				header_obj.master_iv_seed.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				),
				seq,
				header_obj.random_value.to_bytes(
					ctypes.sizeof(ctypes.c_uint64),
					endian
				)
			),
			pt_bytes[-libcrytwi.constants.GCM_TAG_SIZE:],
			seq,
			header_obj.flags
		)
		merger(out_f, d_bytes, seq)
		ofs = enc_f.tell()
		seq += 1

	out_f.seek(os.SEEK_SET, os.SEEK_END)
	out_f_len = out_f.tell()
	if out_f_len != ori_payload_len:
		print(f"[!] I wrote {out_f_len}, but record is {ori_payload_len}.")
		raise Exception()
	print(f"[*] I successfully wrote {out_f_len}, and record is {ori_payload_len}.")
finally:
	enc_f.close()
	out_f.close()
