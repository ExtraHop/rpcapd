param (
    [parameter(mandatory=$false)][string]$MgmtIP,
    [parameter(mandatory=$true)][string]$RpcapIP,
    [parameter(mandatory=$false)][string]$InputDir,
    [parameter(mandatory=$false)][string]$OutputDir,
    [parameter(mandatory=$false)][string]$ZipUrl,
    [switch]$ConfigOnly,
    [int]$RpcapPort = 2003
)

$erroractionpreference = "stop"

$pfpath = "${Env:ProgramFiles}\rpcapd"
$confpath = "${pfpath}\rpcapd.ini"
$exepath = "`"${pfpath}\rpcapd.exe`" -v -d -f `"${confpath}`""
$pfnames = @("Packet.dll", "pthreadGC2.dll", "wpcap.dll", "rpcapd.exe")
$sysname = "npf.sys"
$service_name = "rpcapd"
if ($ZipUrl -eq "") {
    $ZipUrl = "http://${MgmtIP}/tools/rpcapd-64bit-windows.zip"
}

$config = @"
ActiveClient = $RpcapIP, $RpcapPort`r`n
NullAuthPermit = YES
"@


function CreateTempDir
{
   $tmpDir = [System.IO.Path]::GetTempPath()
   $tmpDir = [System.IO.Path]::Combine($tmpDir,
                                       [System.IO.Path]::GetRandomFileName())

   [System.IO.Directory]::CreateDirectory($tmpDir) | Out-Null

   $tmpDir
}

function WriteConfig
{
    write-host "Writing config file to $confpath..."
    $config | out-file -filepath $confpath -encoding ascii
}

if ($ConfigOnly) {
    WriteConfig
    exit
}

if ($InputDir -eq "") {
    $tmpdir = CreateTempDir
    $zipfile = "${tmpdir}\rpcapd.zip"
    if ($OutputDir -eq "") {
        $unzipped = "${tmpdir}\rpcapd"
    }
    else {
        $cwd = (get-location).path
        $unzipped = "${cwd}\${OutputDir}"
    }
    $client = new-object system.net.webclient
    write-host "Trying to download ${ZipUrl}..."
    $client.downloadfile($ZipUrl, $zipfile)
    write-host "Download succeeded, unzipping to ${unzipped}..."
    try {
        $shell = new-object -com shell.application
        $nothing = new-item -itemtype directory -path $unzipped
        $shell.namespace($unzipped).copyhere($shell.namespace($zipfile).items())
    }
    catch {
        # Server Core?
        write-host ("Unzip using shell failed, falling back to " +
                    "System.IO.Compression.ZipFile (requires .NET 4.5)")
        [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $unzipped)
    }
}
else {
    $unzipped = $InputDir
}

try {
    $nothing = get-item -path $unzipped
}
catch {
    throw "Couldn't find directory ${unzipped}"
}

try {
    $pfdir = get-item -path $pfpath
}
catch {
    $pfdir = new-item -itemtype directory -path $pfpath
}

write-host "Copying files to ${pfpath}..."
$pfnames | foreach-object {
    copy-item -path "${unzipped}\${_}" -destination $pfdir
}
$sysdest = "${Env:SystemRoot}\system32\drivers"
write-host "Copying ${sysname} to ${sysdest}..."
copy-item -path "${unzipped}\${sysname}" -destination $sysdest

WriteConfig

try {
    $serv = get-service -name $service_name
}
catch {
    write-host "Creating $service_name service..."
    $nothing = new-service -name $service_name -binarypathname $exepath `
                           -displayname "Remote Packet Capture (rpcapd)"
}
write-host "Starting $service_name service..."
start-service -name $service_name
write-host "Success!"

