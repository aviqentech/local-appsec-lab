"""Windows source handles: reject reparses and hold directory rename/delete locks."""

from __future__ import annotations

import os
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from local_appsec_lab.errors import ScopeError


def open_source(root: Path, relative: Path, parents_only=False):
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]

    class Information(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME),
            ("written", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    info_fn = kernel.GetFileInformationByHandle
    info_fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(Information)]
    info_fn.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    handles = []
    if str(root).startswith("\\\\") or any(":" in part for part in relative.parts):
        raise ScopeError("Source reads require a local disk and ordinary file paths")
    try:
        # Omit FILE_SHARE_DELETE so opened ancestors cannot be renamed/replaced.
        parts = [
            root.anchor,
            *root.parts[1:],
            *(relative.parts[:-1] if parents_only else relative.parts),
        ]
        cursor = Path(parts[0])
        for index, part in enumerate(parts):
            if index:
                cursor /= part
            final = index == len(parts) - 1 and not parents_only
            handle = create(
                str(cursor),
                0x80000000 if final else 0x80,
                3,
                None,
                3,
                0x00200000 | 0x02000000,
                None,
            )  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
            if handle == invalid:
                raise ScopeError("Source directory/file changed or cannot be safely opened")
            handles.append(handle)
            information = Information()
            if not info_fn(handle, ctypes.byref(information)):
                raise ScopeError("Cannot inspect source handle")
            if information.attributes & 0x400:
                raise ScopeError("Windows junctions and other reparse points are prohibited")
            if final and (information.attributes & 0x10 or information.links != 1):
                raise ScopeError("Only ordinary, non-hard-linked source files may be read")
        if parents_only:
            result = list(handles)
            handles.clear()
            return result
        result = msvcrt.open_osfhandle(int(handles[-1]), os.O_RDONLY | os.O_BINARY)
        handles.pop()  # Descriptor now owns this handle.
        return result
    finally:
        for handle in reversed(handles):
            close(handle)


@contextmanager
def hold_parents(root: Path, relative: Path):
    import ctypes
    from ctypes import wintypes

    handles = open_source(root, relative, parents_only=True)
    close = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close.argtypes = [wintypes.HANDLE]
    try:
        yield
    finally:
        for handle in reversed(handles):
            close(handle)


@lru_cache(maxsize=1)
def current_sid():
    import ctypes
    from ctypes import wintypes

    kernel, security = (
        ctypes.WinDLL("kernel32", use_last_error=True),
        ctypes.WinDLL("advapi32", use_last_error=True),
    )
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    security.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    security.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_uint,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token, length = wintypes.HANDLE(), wintypes.DWORD()
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "Cannot query current user security token")
    try:
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise OSError(ctypes.get_last_error(), "Cannot read user SID")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "Cannot format user SID")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


def secure_path(path: Path, directory=True):
    """Set an exact protected user/SYSTEM DACL; POSIX chmod alone does not protect Windows files."""
    import ctypes
    from ctypes import wintypes

    security, kernel = (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
    )
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    security.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    security.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_uint,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    security.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    inheritance = "OICI" if directory else ""
    sddl = f"D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;{current_sid()})"
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise OSError(ctypes.get_last_error(), "Cannot create private Windows security descriptor")
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not security.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "Cannot read private Windows DACL")
        result = security.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None)
        if result:
            raise OSError(result, "Cannot enforce private Windows artifact permissions")
    finally:
        kernel.LocalFree(descriptor)
