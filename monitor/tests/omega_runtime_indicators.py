"""Controlled non-root indicators for a local Oma/Falco test (no socket-file access)."""

import ctypes
import socket


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        try:
            connection.connect(("127.0.0.1", 9))
            print("Outbound connect completed")
        except OSError as error:
            print("Outbound connect attempted:", type(error).__name__)

    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    result = libc.unshare(0x00020000)  # CLONE_NEWNS; a denied attempt is a signal.
    print("unshare(CLONE_NEWNS) result:", result, "errno:", ctypes.get_errno())


if __name__ == "__main__":
    main()
