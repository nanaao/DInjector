using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Generic;

namespace DInjector
{
    class Syscalls
    {
        public static NTSTATUS NtOpenProcess(ref IntPtr ProcessHandle, DI.Data.Win32.Kernel32.ProcessAccessFlags DesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID ClientId)
        {
            // { API_HASHING:ZwOpenProcess }
            IntPtr stub = GetSyscallStub("db73f4d0e9b30d2395e9c590efae3992", 0x9ae1a3c9);
            Delegates.NtOpenProcess ntOpenProcess = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtOpenProcess));

            return ntOpenProcess(
                ref ProcessHandle,
                DesiredAccess,
                ref ObjectAttributes,
                ref ClientId);
        }

        public static NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect)
        {
            // { API_HASHING:ZwAllocateVirtualMemory }
            IntPtr stub = GetSyscallStub("c7a3344f2cf2bad250ecff3856b25d37", 0xd148b632);
            Delegates.NtAllocateVirtualMemory ntAllocateVirtualMemory = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtAllocateVirtualMemory));

            if (ProcessHandle == IntPtr.Zero)
                return ntAllocateVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ZeroBits,
                    ref RegionSize,
                    AllocationType,
                    Protect);

            return ntAllocateVirtualMemory(
                ProcessHandle,
                ref BaseAddress,
                ZeroBits,
                ref RegionSize,
                AllocationType,
                Protect);
        }

        public static NTSTATUS NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint BufferLength, ref uint BytesWritten)
        {
            // { API_HASHING:ZwWriteVirtualMemory }
            IntPtr stub = GetSyscallStub("8e828711ed73393ff048ce49e70d8341", 0x5f2f2235);
            Delegates.NtWriteVirtualMemory ntWriteVirtualMemory = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtWriteVirtualMemory));

            return ntWriteVirtualMemory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                BufferLength,
                ref BytesWritten);
        }

        public static NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
        {
            // { API_HASHING:ZwProtectVirtualMemory }
            IntPtr stub = GetSyscallStub("afa815f8f39637e38560645048e42001", 0x579ce9bc);
            Delegates.NtProtectVirtualMemory ntProtectVirtualMemory = (Delegates.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtProtectVirtualMemory));

            if (ProcessHandle == IntPtr.Zero)
                return ntProtectVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ref RegionSize,
                    NewProtect,
                    ref OldProtect);

            return ntProtectVirtualMemory(
                ProcessHandle,
                ref BaseAddress,
                ref RegionSize,
                NewProtect,
                ref OldProtect);
        }

        public static NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            // { API_HASHING:ZwCreateThreadEx }
            IntPtr stub = GetSyscallStub("67a61cbadac070a16d11395a4999a1e1", 0x11484a6a);
            Delegates.NtCreateThreadEx ntCreateThreadEx = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateThreadEx));

            if (processHandle == IntPtr.Zero)
                return ntCreateThreadEx(
                    ref threadHandle,
                    desiredAccess,
                    objectAttributes,
                    Process.GetCurrentProcess().Handle,
                    startAddress,
                    parameter,
                    createSuspended,
                    stackZeroBits,
                    sizeOfStack,
                    maximumStackSize,
                    attributeList);

            return ntCreateThreadEx(
                ref threadHandle,
                desiredAccess,
                objectAttributes,
                processHandle,
                startAddress,
                parameter,
                createSuspended,
                stackZeroBits,
                sizeOfStack,
                maximumStackSize,
                attributeList);
        }

        public static NTSTATUS NtCreateThreadExDelegate(ref IntPtr threadHandle, DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, Delegate startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            // { API_HASHING:ZwCreateThreadEx }
            IntPtr stub = GetSyscallStub("ac5431afe95573b0f5ec95f9bb9d231a", 0xabdcf862);
            Delegates.NtCreateThreadExDelegate ntCreateThreadExDelegate = (Delegates.NtCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateThreadExDelegate));

            return ntCreateThreadExDelegate(
                ref threadHandle,
                desiredAccess,
                objectAttributes,
                Process.GetCurrentProcess().Handle,
                startAddress,
                parameter,
                createSuspended,
                stackZeroBits,
                sizeOfStack,
                maximumStackSize,
                attributeList);
        }

        public static NTSTATUS NtDelayExecution(bool Alertable, ref Win32.LARGE_INTEGER DelayInterval)
        {
            // { API_HASHING:ZwDelayExecution }
            IntPtr stub = GetSyscallStub("cc11363dbd7f123d57c9775bb49bded9", 0x85f63c32);
            Delegates.NtDelayExecution ntDelayExecution = (Delegates.NtDelayExecution)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtDelayExecution));

            return ntDelayExecution(
                Alertable,
                ref DelayInterval);
        }

        public static NTSTATUS NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, ref Win32.LARGE_INTEGER Timeout)
        {
            // { API_HASHING:ZwWaitForSingleObject }
            IntPtr stub = GetSyscallStub("cac61f9687beb649cfc212a6cd1dd1a5", 0xc4303afd);
            Delegates.NtWaitForSingleObject ntWaitForSingleObject = (Delegates.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtWaitForSingleObject));

            return ntWaitForSingleObject(
                ObjectHandle,
                Alertable,
                ref Timeout);
        }

        public static NTSTATUS NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
        {
            // { API_HASHING:ZwFreeVirtualMemory }
            IntPtr stub = GetSyscallStub("c5c1ee5719b574d0026bf229a4d84db9", 0x8b6018d5);
            Delegates.NtFreeVirtualMemory ntFreeVirtualMemory = (Delegates.NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtFreeVirtualMemory));

            if (processHandle == IntPtr.Zero)
                return ntFreeVirtualMemory(
                    Process.GetCurrentProcess().Handle,
                    ref baseAddress,
                    ref regionSize,
                    freeType);

            return ntFreeVirtualMemory(
                processHandle,
                ref baseAddress,
                ref regionSize,
                freeType);
        }

        public static NTSTATUS NtFlushInstructionCache(IntPtr ProcessHandle, ref IntPtr BaseAddress, uint NumberOfBytesToFlush)
        {
            // { API_HASHING:ZwFlushInstructionCache }
            IntPtr stub = GetSyscallStub("6bb170968115d7fc72d377c03cb3e9ac", 0x481017aa);
            Delegates.NtFlushInstructionCache ntFlushInstructionCache = (Delegates.NtFlushInstructionCache)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtFlushInstructionCache));

            if (ProcessHandle == IntPtr.Zero)
                return ntFlushInstructionCache(
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    NumberOfBytesToFlush);

            return ntFlushInstructionCache(
                ProcessHandle,
                ref BaseAddress,
                NumberOfBytesToFlush);
        }

        public static NTSTATUS NtQueryInformationProcess(IntPtr ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation, uint ProcessInformationLength, ref uint ReturnLength)
        {
            // { API_HASHING:ZwQueryInformationProcess }
            IntPtr stub = GetSyscallStub("3166f02f8f7ff32c460978fae14e3a8f", 0x8fa36ed0);
            Delegates.NtQueryInformationProcess ntQueryInformationProcess = (Delegates.NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtQueryInformationProcess));

            return ntQueryInformationProcess(
                ProcessHandle,
                ProcessInformationClass,
                ref ProcessInformation,
                ProcessInformationLength,
                ref ReturnLength);
        }

        public static NTSTATUS NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToRead, ref uint NumberOfBytesReaded)
        {
            // { API_HASHING:ZwReadVirtualMemory }
            IntPtr stub = GetSyscallStub("dac2b7306821944feec16196e97e4a9a", 0x527a63bb);
            Delegates.NtReadVirtualMemory ntReadVirtualMemory = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtReadVirtualMemory));

            return ntReadVirtualMemory(
                ProcessHandle,
                BaseAddress,
                Buffer,
                NumberOfBytesToRead,
                ref NumberOfBytesReaded);
        }

        public static NTSTATUS NtResumeThread(IntPtr ThreadHandle, ref uint SuspendCount)
        {
            // { API_HASHING:ZwResumeThread }
            IntPtr stub = GetSyscallStub("feba8b576a2bc60cc3b60282852d2d69", 0x369d4fb8);
            Delegates.NtResumeThread ntResumeThread = (Delegates.NtResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtResumeThread));

            return ntResumeThread(
                ThreadHandle,
                ref SuspendCount);
        }

        public static NTSTATUS NtOpenThread(ref IntPtr ThreadHandle, DI.Data.Win32.Kernel32.ThreadAccess dwDesiredAccess, ref Win32.OBJECT_ATTRIBUTES ObjectAttributes, ref Win32.CLIENT_ID ClientId)
        {
            // { API_HASHING:ZwOpenThread }
            IntPtr stub = GetSyscallStub("a66de7dfbf11638dfa142dbfae6e308a", 0x6d64dd95);
            Delegates.NtOpenThread ntOpenThread = (Delegates.NtOpenThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtOpenThread));

            return ntOpenThread(
                ref ThreadHandle,
                dwDesiredAccess,
                ref ObjectAttributes,
                ref ClientId);
        }

        public static NTSTATUS NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
        {
            // { API_HASHING:ZwQueueApcThread }
            IntPtr stub = GetSyscallStub("9a87aeef20b3bcd9cd49721182b9237e", 0xfb7727c7);
            Delegates.NtQueueApcThread ntQueueApcThread = (Delegates.NtQueueApcThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtQueueApcThread));

            return ntQueueApcThread(
                ThreadHandle,
                ApcRoutine,
                ApcArgument1,
                ApcArgument2,
                ApcArgument3);
        }

        public static NTSTATUS NtAlertResumeThread(IntPtr ThreadHandle, ref uint SuspendCount)
        {
            // { API_HASHING:ZwAlertResumeThread }
            IntPtr stub = GetSyscallStub("c35558ab2636113572eeb9fc5c0b72e9", 0xa01508e0);
            Delegates.NtAlertResumeThread ntAlertResumeThread = (Delegates.NtAlertResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtAlertResumeThread));

            return ntAlertResumeThread(
                ThreadHandle,
                ref SuspendCount);
        }

        public static NTSTATUS NtGetContextThread(IntPtr hThread, ref Registers.CONTEXT64 lpContext)
        {
            // { API_HASHING:ZwGetContextThread }
            IntPtr stub = GetSyscallStub("6de00a46513c07212b176678537e216b", 0x1c4aef8d);
            Delegates.NtGetContextThread ntGetContextThread = (Delegates.NtGetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtGetContextThread));

            return ntGetContextThread(
                hThread,
                ref lpContext);
        }

        public static NTSTATUS NtSetContextThread(IntPtr hThread, ref Registers.CONTEXT64 lpContext)
        {
            // { API_HASHING:ZwSetContextThread }
            IntPtr stub = GetSyscallStub("337d7f16799e242a618381f17279d235", 0xcc4fec3);
            Delegates.NtSetContextThread ntSetContextThread = (Delegates.NtSetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtSetContextThread));

            return ntSetContextThread(
                hThread,
                ref lpContext);
        }

        public static NTSTATUS NtCreateSection(ref IntPtr SectionHandle, DI.Data.Win32.WinNT.ACCESS_MASK DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle)
        {
            // { API_HASHING:ZwCreateSection }
            IntPtr stub = GetSyscallStub("f01caffc2286b0ca42fd556b0154b52f", 0x253059dc);
            Delegates.NtCreateSection ntCreateSection = (Delegates.NtCreateSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtCreateSection));

            return ntCreateSection(
                ref SectionHandle,
                DesiredAccess,
                ObjectAttributes,
                ref MaximumSize,
                SectionPageProtection,
                AllocationAttributes,
                FileHandle);
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref ulong SectionOffset, ref uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect)
        {
            // { API_HASHING:ZwMapViewOfSection }
            IntPtr stub = GetSyscallStub("dd8f624e34069db95e355b2672ce2ef1", 0xdf3607df);
            Delegates.NtMapViewOfSection ntMapViewOfSection = (Delegates.NtMapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtMapViewOfSection));

            if (ProcessHandle == IntPtr.Zero)
                return ntMapViewOfSection(
                    SectionHandle,
                    Process.GetCurrentProcess().Handle,
                    ref BaseAddress,
                    ZeroBits,
                    CommitSize,
                    ref SectionOffset,
                    ref ViewSize,
                    InheritDisposition,
                    AllocationType,
                    Win32Protect);

            return ntMapViewOfSection(
                SectionHandle,
                ProcessHandle,
                ref BaseAddress,
                ZeroBits,
                CommitSize,
                ref SectionOffset,
                ref ViewSize,
                InheritDisposition,
                AllocationType,
                Win32Protect);
        }

        public static NTSTATUS NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress)
        {
            // { API_HASHING:ZwUnmapViewOfSection }
            IntPtr stub = GetSyscallStub("c036be5efc94532cd79199cbc0aaf471", 0xfe8f943d);
            Delegates.NtUnmapViewOfSection ntUnmapViewOfSection = (Delegates.NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtUnmapViewOfSection));

            if (ProcessHandle == IntPtr.Zero)
                return ntUnmapViewOfSection(
                    Process.GetCurrentProcess().Handle,
                    BaseAddress);

            return ntUnmapViewOfSection(
                ProcessHandle,
                BaseAddress);
        }

        public static NTSTATUS NtClose(IntPtr ObjectHandle)
        {
            // { API_HASHING:ZwClose }
            IntPtr stub = GetSyscallStub("2b26326d7df2e8ec642c9692f8f2ad45", 0x88dc5794);
            Delegates.NtClose ntClose = (Delegates.NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtClose));

            return ntClose(ObjectHandle);
        }
    }
}