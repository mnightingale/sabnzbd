#!/usr/bin/python3

"""
Functions to check if a path supports sparse files
"""
import sys
import os
import tempfile

if sys.platform == "win32":
    import msvcrt
    import ctypes
    from ctypes import wintypes

    # Win32 constants
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
    FSCTL_SET_SPARSE = 0x000900C4  # FSCTL_SET_SPARSE from winioctl.h
    FILE_BEGIN = 0
    FILE_CURRENT = 1
    FILE_END = 2

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Function signatures
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,  # hDevice
        wintypes.DWORD,  # dwIoControlCode
        wintypes.LPVOID,  # lpInBuffer
        wintypes.DWORD,  # nInBufferSize
        wintypes.LPVOID,  # lpOutBuffer
        wintypes.DWORD,  # nOutBufferSize
        ctypes.POINTER(wintypes.DWORD),  # lpBytesReturned
        wintypes.LPVOID,  # lpOverlapped (can be NULL)
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL

    # SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD)
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL

    # SetEndOfFile(HANDLE)
    kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    kernel32.SetEndOfFile.restype = wintypes.BOOL


def _raise_last_win_error(msg=None):
    """Raise OSError with last Win32 error and optional message prefix."""
    err = ctypes.get_last_error()
    if msg:
        raise OSError(err, f"{msg}: {ctypes.FormatError(err)}")
    else:
        raise OSError(err, ctypes.FormatError(err))


def is_sparse(path: str) -> bool:
    stat = os.stat(path)
    if "win32" in sys.platform:
        return bool(stat.st_file_attributes & FILE_ATTRIBUTE_SPARSE_FILE)

    # Linux and macOS
    if stat.st_blocks * 512 < stat.st_size:
        return True

    # Filesystem with SEEK_HOLE (ZFS)
    try:
        with open(path, "rb") as f:
            pos = f.seek(0, os.SEEK_HOLE)
            return pos < stat.st_size
    except (AttributeError, OSError):
        pass

    return False


def _sparse_win32(fd: int, length: int):
    """
    Mark a file as sparse, then increase logical file size by `length` bytes
    without writing data; finally restore original file position.

    Parameters
    ----------
    fd : int
        The file descriptor to operate on.
    length : int
        Number of bytes to increase the file length by.
    """
    if length < 0:
        raise ValueError("length must be non-negative")

    # Get OS file handle from a file descriptor
    handle = msvcrt.get_osfhandle(fd)
    if handle == -1 or handle is None:
        raise OSError("Invalid file descriptor / handle")

    # Try to mark sparse (it's OK if this fails)
    bytes_returned = wintypes.DWORD(0)
    if not kernel32.DeviceIoControl(
        wintypes.HANDLE(handle), wintypes.DWORD(FSCTL_SET_SPARSE), None, 0, None, 0, ctypes.byref(bytes_returned), None
    ):
        # Making file sparse failed
        return False

    # Save current file pointer
    cur_pos = ctypes.c_longlong(0)
    if not kernel32.SetFilePointerEx(wintypes.HANDLE(handle), 0, ctypes.byref(cur_pos), FILE_CURRENT):
        _raise_last_win_error("SetFilePointerEx (get current position) failed")

    # Move to (END + length)
    li_size = ctypes.c_longlong(length)
    if not kernel32.SetFilePointerEx(wintypes.HANDLE(handle), li_size, None, FILE_END):
        _raise_last_win_error("SetFilePointerEx (move to end+length) failed")

    # Set end of file to current pointer
    if not kernel32.SetEndOfFile(wintypes.HANDLE(handle)):
        _raise_last_win_error("SetEndOfFile failed")

    # Restore original position
    if not kernel32.SetFilePointerEx(wintypes.HANDLE(handle), cur_pos, None, FILE_BEGIN):
        _raise_last_win_error("SetFilePointerEx (restore position) failed")

    return True


def sparse(fd: int, size: int):
    """Make a file sparse"""
    if "win32" in sys.platform:
        _sparse_win32(fd, size)
    else:
        os.ftruncate(fd, size)


def is_sparse_supported(check_dir: str) -> bool:
    sparse_file = tempfile.NamedTemporaryFile(dir=check_dir, delete=False)
    try:
        sparse(sparse_file.fileno(), 64)
        sparse_file.close()
        return is_sparse(sparse_file.name)
    finally:
        os.unlink(sparse_file.name)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        DIRNAME = sys.argv[1]
        if not os.path.isdir(DIRNAME):
            print("Specified argument is not a directory. Bailing out")
            sys.exit(1)
    else:
        # no argument, so use current working directory
        DIRNAME = os.getcwd()
        print("Using current working directory")

    if is_sparse_supported(DIRNAME):
        print("%s supports sparse files" % DIRNAME)
    else:
        print("%s does not support sparse files" % DIRNAME)
