# SPDX-License-Identifier: Apache-2.0
"""Inspect private Windows files and directories using their native ACLs."""

from pathlib import Path

import pywintypes
import win32api
import win32con
import win32file
import win32security


def _check_acl(handle):
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
    finally:
        token.Close()

    trusted = (
        user,
        win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None),
        win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None),
    )
    security = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    acl = security.GetSecurityDescriptorDacl()
    if security.GetSecurityDescriptorOwner() not in trusted or acl is None:
        raise ValueError("Windows ownership or ACL is not private")
    # Python's mkdir(0o700) grants access to the verified owner via OWNER RIGHTS.
    allowed = (*trusted, win32security.ConvertStringSidToSid("S-1-3-4"))
    for index in range(acl.GetAceCount()):
        header, *fields = acl.GetAce(index)
        ace_type, flags = header
        if flags & win32security.INHERIT_ONLY_ACE or ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE or fields[-1] not in allowed:
            raise ValueError("Windows ACL grants access outside the current user and system administrators")


def _open_private(path: Path, *, directory: bool, read: bool):
    access = win32con.READ_CONTROL
    if read:
        access |= win32con.GENERIC_READ
    flags = win32file.FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= win32con.FILE_FLAG_BACKUP_SEMANTICS
    handle = win32file.CreateFile(
        str(path), access,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None, win32con.OPEN_EXISTING, flags, None,
    )
    try:
        attributes = win32file.GetFileInformationByHandle(handle)[0]
        if (attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT
                or bool(attributes & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory
                or win32file.GetFileType(handle) != win32file.FILE_TYPE_DISK):
            raise ValueError("Expected a regular Windows file or directory")
        _check_acl(handle)
    except BaseException:
        handle.Close()
        raise
    return handle


def check_private(path: Path, *, directory: bool = False) -> None:
    try:
        _open_private(path, directory=directory, read=False).Close()
    except pywintypes.error as exc:
        raise OSError(exc.winerror, exc.strerror) from None


def read_private(path: Path, limit: int) -> bytes:
    try:
        handle = _open_private(path, directory=False, read=True)
        try:
            if win32file.GetFileSize(handle) > limit:
                raise ValueError("Credential exceeds size limit")
            _, raw = win32file.ReadFile(handle, limit + 1)
            return raw
        finally:
            handle.Close()
    except pywintypes.error as exc:
        raise OSError(exc.winerror, exc.strerror) from None
