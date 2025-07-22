"""cli.py is for commandline arguments parsing."""
import argparse
from crytwi import __version__


def build_args():
	parser = argparse.ArgumentParser(
		prog='crytwi',
		description='A tool for encrypting and decrypting single files.',
		epilog='Version 0.0.1 - for more information,'
		' visit https://github.com/lishxlin/crytwi-py')
	parser.add_argument(
		'-V', '--version', dest='func', action='store_const', const=print_version,
		help='Show version and exit')

	subparsers = parser.add_subparsers(
		dest='command', metavar='COMMAND')

	# encrypt
	p_encrypt = subparsers.add_parser('encrypt', help='Encrypt a file')
	p_encrypt.add_argument('-i', '--input', required=True, help='Input file path')
	p_encrypt.add_argument(
		'-o', '--output', required=True, help='Encrypted output file path')
	p_encrypt.add_argument(
		'-k', '--key', required=True, help='Encryption key or key file')

	# decrypt
	p_decrypt = subparsers.add_parser('decrypt', help='Decrypt a file')
	p_decrypt.add_argument(
		'-i', '--input', required=True, help='Encrypted file path')
	p_decrypt.add_argument(
		'-o', '--output', required=True, help='Decrypted output file path')
	p_decrypt.add_argument(
		'-k', '--key', required=True, help='Decryption key or key file')

	return parser


def print_version(args=None):
	print(f"crytwi {__version__}")


def main():
	parser = build_args()
	args = parser.parse_args()

	func = getattr(args, 'func', None)
	if func:
		func(args)
	elif args.command is None:
		parser.print_help()
