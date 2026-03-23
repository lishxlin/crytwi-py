import ctypes


CLR_RESET = "\033[0;0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_BLUE = "\033[34m"
CLR_CYAN = "\033[36m"
CLR_GRAY = "\033[90m"

CLR_ERROR = CLR_BOLD + CLR_RED
CLR_SUCCESS = CLR_BOLD + CLR_GREEN
CLR_INFO = CLR_CYAN


def get_uint_max(ctypes_type):
	return (1 << (ctypes.sizeof(ctypes_type) * 8)) - 1
