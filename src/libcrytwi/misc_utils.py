import ctypes


def get_uint_max(ctypes_type):
	return (1 << (ctypes.sizeof(ctypes_type) * 8)) - 1
