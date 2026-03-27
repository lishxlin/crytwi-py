__version__ = '0.0.1-alpha'
__author__ = 'ShXlin Li'

# from .constants import (
# 	MAGICNUM,
# 	SIGNATURE,
# 	PROBE_SIZE,
# 	ENDIAN,
# 	FORMAT_VERSION,
# 	CIPHER_TYPE,
# 	DEBUG_FLAG,
# 	TOTAL_TRAILER_READ_SIZE,
# 	GCM_TAG_SIZE,
# 	TRAILER_PATTERN_7B,
# 	CHUNK0_PATTERN_4B_FINAL,
# 	CHUNK0_PATTERN_4B_NON_FINAL
# )
from .structs import (
	CrytwiDynamicMetaHeader,
	CrytwiFixedChunkStruct,
	CrytwiFixedMetaHeader
	# META_FIXED_HEADER_SIZE,
	# META_DYNAMIC_HEADER_SIZE,
	# CHUNK_FIXED_HEADER_SIZE
)
from .header import (
	assemble_fixed_meta_header,
	assemble_dynamic_meta_header,
	extract_meta_header,
	format_compat,
	dy_vla_cipher
)
from .crypto import (
	init_kdf_params,
	generate_header_entropy,
	derive_kdf_material,
	derive_chunk_iv,
	vla_decryptor,
	chunk_encryptor,
	chunk_decryptor,
	chunk_validator
)
from .io_utils import (
	early_io_loader,
	compute_processor_map,
	file_splitter,
	generate_chunk,
	build_trailer,
	merge_chunks,
	chunks_format_checker,
	prep_chunk_extract
)
from .misc_utils import (
	get_uint_max
)
from .security import (
	get_pass,
	burn_mem
)

__all__ = [
	# Structs
	'CrytwiDynamicMetaHeader', 'CrytwiFixedChunkStruct', 'CrytwiFixedMetaHeader',

	# Header
	'assemble_fixed_meta_header', 'assemble_dynamic_meta_header',
	'extract_meta_header', 'format_compat', 'dy_vla_cipher',

	# Crypto
	'init_kdf_params', 'generate_header_entropy', 'derive_kdf_material',
	'derive_chunk_iv', 'vla_decryptor', 'chunk_encryptor',
	'chunk_decryptor', 'chunk_validator',

	# IO & Utils
	'early_io_loader', 'compute_processor_map', 'file_splitter',
	'generate_chunk', 'build_trailer', 'merge_chunks',
	'chunks_format_checker', 'prep_chunk_extract', 'get_uint_max',

	# Security
	'get_pass', 'burn_mem',
]
