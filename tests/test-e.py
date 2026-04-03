import libcrytwi
import os
import errno

print(f"Version: {libcrytwi.__version__}")

raw_f = open("parts-tests-files/koishi.png", "rb")
# get size
raw_f.seek(os.SEEK_SET, os.SEEK_END)
raw_f_len = raw_f.tell()  # the raw size
# seek back
raw_f.seek(os.SEEK_SET)

kdf_params = libcrytwi.init_kdf_params()
if kdf_params == errno.EINVAL:
	raise Exception(kdf_params)

entrophy = libcrytwi.generate_header_entropy()

fixed_header = libcrytwi.assemble_fixed_meta_header(
	entropies=entrophy,
	kdf_params=kdf_params,
	payload_len=raw_f_len,
	manage_flag=0x01
)

out_f = open("parts-tests-files/single-py.test", "wb")
out_f.write(fixed_header)

kdfs = libcrytwi.derive_kdf_material(
	pwd_buf=libcrytwi.get_pass(),
	entropies=entrophy,
	kdf_params=kdf_params
)

alias_str = "tests"
filename_str = os.path.basename(raw_f.name)

print(f"Input alias is {alias_str}, filename is {filename_str}")

dynamic_header = libcrytwi.assemble_dynamic_meta_header(
	manage_flag=0x01,
	non_encrypt_meta_infos=(alias_str, filename_str),
	kdf_key=kdfs[0],
	iv_seed=entrophy[1]
)
out_f.write(dynamic_header)

try:
	CPM = libcrytwi.compute_processor_map(
		file_raw_size=raw_f_len,
	)
	chunk_nums = len(CPM)
	merge_chunks = libcrytwi.init_merger()
	for item in CPM:
		for cseq, offset in item.items():
			raw_bytes = libcrytwi.file_splitter(
				file=raw_f,
				offset=offset
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
					cseq
				)
				if chunk_bytes == errno.EPROTOTYPE:
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
