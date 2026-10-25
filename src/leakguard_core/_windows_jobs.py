"""Windows Job Object ownership for bounded parser/extension subprocesses.

Create the process suspended, assign the job, then resume its owned thread. Job
limits apply before input code runs. This is resource containment, not a sandbox.

API references:
https://learn.microsoft.com/windows/win32/procthread/job-objects
https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes


class JobUnavailable(RuntimeError):
    def __init__(self):
        super().__init__('resource-bound-unavailable')


def _api():
    # Importing this module is inert and works on non-Windows hosts for tooling.
    try:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    except (AttributeError, OSError):
        raise JobUnavailable() from None
    signatures = {
        'CreateJobObjectW': ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
        'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
        'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
        'OpenProcess': ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        'CreateToolhelp32Snapshot': ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
        'Thread32First': ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
        'Thread32Next': ([wintypes.HANDLE, ctypes.c_void_p], wintypes.BOOL),
        'OpenThread': ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        'GetProcessIdOfThread': ([wintypes.HANDLE], wintypes.DWORD),
        'ResumeThread': ([wintypes.HANDLE], wintypes.DWORD),
    }
    for name, (arguments, result) in signatures.items():
        method = getattr(kernel, name)
        method.argtypes = arguments
        method.restype = result
    return kernel


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ('PerProcessUserTimeLimit', ctypes.c_int64),
        ('PerJobUserTimeLimit', ctypes.c_int64),
        ('LimitFlags', wintypes.DWORD),
        ('MinimumWorkingSetSize', ctypes.c_size_t),
        ('MaximumWorkingSetSize', ctypes.c_size_t),
        ('ActiveProcessLimit', wintypes.DWORD),
        ('Affinity', ctypes.c_size_t),
        ('PriorityClass', wintypes.DWORD),
        ('SchedulingClass', wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
        'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ('BasicLimitInformation', _BasicLimits), ('IoInfo', _IoCounters),
        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t),
    ]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
        ('th32ThreadID', wintypes.DWORD), ('th32OwnerProcessID', wintypes.DWORD),
        ('tpBasePri', wintypes.LONG), ('tpDeltaPri', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
    ]


class WindowsJob:
    def __init__(self, memory_bytes):
        self.kernel = _api()
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise JobUnavailable()
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if memory_bytes is not None:
            limits.BasicLimitInformation.LimitFlags |= 0x0100 | 0x0200  # PROCESS_MEMORY | JOB_MEMORY
            limits.ProcessMemoryLimit = memory_bytes
            limits.JobMemoryLimit = memory_bytes
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise JobUnavailable()

    def attach_and_resume(self, process):
        # AssignProcessToJobObject requires SET_QUOTA and TERMINATE access.
        handle = self.kernel.OpenProcess(0x0100 | 0x0001, False, process.pid)
        if not handle:
            raise JobUnavailable()
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, handle):
                raise JobUnavailable()
        finally:
            self.kernel.CloseHandle(handle)
        snapshot = self.kernel.CreateToolhelp32Snapshot(0x00000004, 0)  # SNAPTHREAD
        if snapshot in (None, ctypes.c_void_p(-1).value):
            raise JobUnavailable()
        resumed = 0
        try:
            entry = _ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            available = self.kernel.Thread32First(snapshot, ctypes.byref(entry))
            while available:
                if entry.th32OwnerProcessID == process.pid:
                    # Query owner before resuming to avoid acting on a recycled ID.
                    thread = self.kernel.OpenThread(0x0002 | 0x0800, False, entry.th32ThreadID)
                    if not thread:
                        raise JobUnavailable()
                    try:
                        if self.kernel.GetProcessIdOfThread(thread) != process.pid:
                            raise JobUnavailable()
                        if self.kernel.ResumeThread(thread) != 1:
                            raise JobUnavailable()
                        resumed += 1
                    finally:
                        self.kernel.CloseHandle(thread)
                entry.dwSize = ctypes.sizeof(entry)
                available = self.kernel.Thread32Next(snapshot, ctypes.byref(entry))
            if not resumed:
                raise JobUnavailable()
        finally:
            self.kernel.CloseHandle(snapshot)

    def terminate(self):
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
