import argparse
from . import __version__
from . import __author__
import libcrytwi
import ctypes
import os
import errno
import subprocess


def encrypt(args):
	print("I am going to encrypt a file!")
	print(f"Version: {libcrytwi.__version__}")

	raw_f = open(args.input[0], "rb")
	# get size
	raw_f.seek(os.SEEK_SET, os.SEEK_END)
	raw_f_len = raw_f.tell()  # the raw size
	# seek back
	raw_f.seek(os.SEEK_SET)

	kdf_params = libcrytwi.init_kdf_params(
		int(args.at),
		int(args.ap),
		int(args.ac),
		int(args.sn),
		int(args.sr),
		int(args.sp)
	)
	if kdf_params == errno.EINVAL:
		raise Exception(kdf_params)

	entrophy = libcrytwi.generate_header_entropy()

	fixed_header = libcrytwi.assemble_fixed_meta_header(
		entropies=entrophy,
		kdf_params=kdf_params,
		payload_len=raw_f_len,
		max_chunk_size=int(args.max_chunk_size)
	)

	out_f = open(args.output, "wb")
	out_f.write(fixed_header)

	kdfs = libcrytwi.derive_kdf_material(
		pwd_buf=libcrytwi.get_pass(),
		entropies=entrophy,
		kdf_params=kdf_params
	)

	try:
		CPM = libcrytwi.compute_processor_map(
			file_raw_size=raw_f_len,
			max_chunk_size=int(args.max_chunk_size)
		)
		chunk_nums = len(CPM)
		merge_chunks = libcrytwi.init_merger()
		for item in CPM:
			for cseq, offset in item.items():
				raw_bytes = libcrytwi.file_splitter(
					file=raw_f,
					offset=offset,
					length=int(args.max_chunk_size)
				)
				if raw_bytes == errno.EIO:
					raise Exception(raw_bytes)
				encrypted_bytes = libcrytwi.chunk_encryptor(
					raw_data=raw_bytes,
					seq=cseq,
					key=kdfs[1],
					iv=libcrytwi.derive_chunk_iv(
						entrophy[1],
						cseq,
						entrophy[2]
					)
				)
				if cseq == (chunk_nums - 1):
					chunk_bytes = libcrytwi.generate_chunk(
						encrypted_bytes,
						cseq,
						final_flag=0x01,
						non_tag_length=int((raw_f_len - offset))
					)
					if chunk_bytes == errno.EPROTOTYPE:
						raise Exception(chunk_bytes)
				else:
					chunk_bytes = libcrytwi.generate_chunk(
						encrypted_bytes,
						cseq,
						non_tag_length=int(args.max_chunk_size)
					)
					if chunk_bytes == errno.EPROTOTYPE:
						raise Exception(chunk_bytes)
				if type(chunk_bytes) is not bytes:
					raise Exception(chunk_bytes)
				merge_chunks(
					out_f,
					chunk_bytes,
					cseq
				)
		merge_chunks(
			out_f,
			libcrytwi.build_trailer(chunk_nums),
			chunk_nums
		)
	finally:
		raw_f.close()
		out_f.close()


def decrypt(args):
	print("I am going to decrypt a file!")
	print(f"Version: {libcrytwi.__version__}")
	enc_f = open(args.input[0], "rb")
	out_f = open(args.output, "wb")

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


def main():
	parser = argparse.ArgumentParser(
		description='A Command-line tool that encrypt or decrypt a file.',
		epilog='An example Command-line tool to manipulate libcrytwi.',
		allow_abbrev=False,
		formatter_class=argparse.RawDescriptionHelpFormatter
	)
	parser.add_argument(
		'-V', '--version',
		action='version',
		version=f'Crytwi {__version__} by {__author__}\n'
		f'libcrytwi {libcrytwi.__version__} by {libcrytwi.__author__}'
	)

	subparser = parser.add_subparsers(
		dest='command',
		help='Actions',
		required=True
	)
	sub1p = subparser.add_parser(
		name='encrypt',
		help='Encrypt a file.'
	)
	sub1p.add_argument(
		'--at',
		default=3,
		help='Time cost for Argon2id KDF'
	)
	sub1p.add_argument(
		'--ap',
		default=1,
		help='Argon2id KDF Parallelism'
	)
	sub1p.add_argument(
		'--ac',
		default=0xFFFF,
		help='Argon2id KDF Memory Cost in kibibytes'
	)
	sub1p.add_argument(
		'--sn',
		default=16384,
		help='Scrypt N cost'
	)
	sub1p.add_argument(
		'--sr',
		default=8,
		help='Scrypt r cost'
	)
	sub1p.add_argument(
		'--sp',
		default=1,
		help='Scrypt p cost'
	)
	sub1p.add_argument(
		'-M', '--max-chunk-size',
		default=(64 * 1024),
		help='Maximum size for a single chunk in bytes. (Max 0xFFFFFFFFFF)'
	)
	sub1p.add_argument(
		'input',
		nargs=1,
		help='The source file.'
	)
	sub1p.add_argument(
		'output',
		default='./a.crytwi',
		nargs='?',
		help="The encrypted file, default output is './a.crytwi.'"
	)
	sub1p.set_defaults(func=encrypt)

	sub2p = subparser.add_parser(
		name='decrypt',
		help='Decrypt a file.'
	)
	sub2p.add_argument(
		'input',
		nargs=1,
		help='The source file.'
	)
	sub2p.add_argument(
		'output',
		default='./a.ctout',
		nargs='?',
		help="The decrypted file, default output is './a.ctout.'"
	)
	sub2p.set_defaults(func=decrypt)

	args = parser.parse_args()

	while True:
		if os.path.isfile(args.output):
			print(f"{args.output} is existed, which operation do you want?")
			print("(c) Cancel this session.")
			print("(r) Let's me rename output.")
			print("(f) Force override it.")
			print("(s) Open a shell.")
			choice = input("Enter your choice: ").lower()
			if choice == 'c':
				exit(0)
			elif choice == 'r':
				args.output = input("New name for it: ")
				break
			elif choice == 'f':
				break
			elif choice == 's':
				user_shell = os.environ.get("SHELL", "/bin/sh")
				subprocess.run([user_shell])
			else:
				print("")
				continue
	args.func(args)


if __name__ == '__main__':
	main()
