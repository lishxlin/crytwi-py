import argparse
from . import __version__
from . import __author__
import libcrytwi
import sys, os


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
		help='Maximum size for a single chunk. (Max 0xFFFFFFFFFF)'
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

	sub2p = subparser.add_parser(
		name='decrypt',
		help='Decrypt a file.'
	)

	args = parser.parse_args()


if __name__ == '__main__':
	main()
