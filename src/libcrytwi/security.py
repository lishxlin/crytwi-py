import getpass
import gc
import ctypes


def get_pass(
	prompt="Enter Master Password: "
) -> bytearray:
	raw_pwd = getpass.getpass(prompt)
	pwd_b = bytearray(raw_pwd.encode('utf-8'))
	raw_pwd = None
	del raw_pwd
	gc.collect()

	return pwd_b
# We need C


def burn_mem(
	buf: bytearray
):
	if buf:
		ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
