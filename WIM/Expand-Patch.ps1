param(
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Patch = "",
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$Destination = "",
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$NoSSU = $false
)

function Expand-Patch{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Patch,
        [String]$Destination,
        [switch]$NoSSU = $false
    )
    begin{
        $x86 = Join-Path -Path $Destination -ChildPath "x86"
        $x64 = Join-Path -Path $Destination -ChildPath "x64"
        $WOW = Join-Path -Path $Destination -ChildPath "WOW64"
        $MSIL = Join-Path -Path $Destination -ChildPath "MSIL"
        $JUNK = Join-Path -Path $Destination -ChildPath "JUNK"
        $BIN = Join-Path -Path $Destination -ChildPath "PATCH"
        $subDirs = @($x86, $x64, $WOW, $MSIL, $JUNK, $BIN)
    }
    process{
        if((-not $Patch) -or (-not (Test-Path $Patch))){
            throw("Provided path to patch is invalid. Please provide a valid path: $Patch")
        }

        $Patch = $(Resolve-Path -Path $Patch).Path
        if(-not $Destination){
            $timestamp = Get-Date -Format yyyyMMddhhmmss
            $Destination = Join-Path -ChildPath $timestamp -Path $(Get-Location)
        }
        else{
            $Destination = Join-Path -ChildPath $Destination -Path $(Get-Location)
        }

        log_i "Extracting to $Destination"

        if(Test-Path -Path $Destination){
            log_i "$Destination already exists."
        }
        else{
            $null = New-Item -Path $Destination -ItemType Directory
            foreach($subDir in $subDirs){
                $null = New-Item -Path $subDir -ItemType Directory
            }
        }
        Expand $Patch $Destination $NoSSU
        # Stow any expanded dlls into PATCH folder
        $dlls = Get-ChildItem -Filter "*.dll" -Path $Destination
        if($dlls){
            Move-Item -Path $dlls.FullName -Destination $BIN -ErrorAction SilentlyContinue
        }
        $exclude = foreach($dir in $subDirs){Split-Path -Path $dir -Leaf}
        $miscFiles = Get-ChildItem -Path $Destination -Exclude $exclude
        foreach($miscFile in $miscFiles){
            Move-Item -Path $miscFile.FullName -Destination $(Normalize $miscFile.Name) -ErrorAction SilentlyContinue
        }
    }
    end{

    }
}

function Expand{
    param(
        [String]$Patch,
        [String]$Destination,
        [switch]$NoSSU
    )
    begin{
        $system32 = Join-Path -Path $(Get-Item -Path $env:windir).FullName -ChildPath "system32"
        $expand = Join-Path -Path $system32 -ChildPath "expand.exe"
        if(-not (Test-Path $expand)){
            throw("Unable to find expand.exe")
        }
        $fs = [System.IO.FileStream]::new($Patch, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    }
    process{
        $headerBytes = [byte[]]::new(5)
        $readBytes = $fs.Read($headerBytes, 0, 5)
        if($readBytes -ge 0){
            $convertedBytes = BytesToString $headerBytes
            switch($convertedBytes){
                "MSCF"{
                    log_s "Patch is in CAB format."
                    $null = Invoke-Expression "$expand -F:* $Patch $Destination"
                }
                "MSWIM"{
                    log_s "Patch is in WIM format."
                    if(IsElevated){
                        # Requires -RunAsAdministrator
                        try {
                            $mountPoint = Join-Path -ChildPath "wimMount" -Path $(Get-Location)
                            $null = New-Item -ItemType Directory $mountPoint
                            log_i "Extracting to $mountPoint"

                            # Mount-WindowsImage requires the provided file to have the extension ".wim"
                            $tempWim = Join-Path -ChildPath "temp.wim" -Path $(Get-Location)
                            Copy-Item -Path $Patch -Destination $tempWim

                            $mounted = Mount-WindowsImage -Path $mountPoint -ImagePath $tempWim -Index 1 -ReadOnly
                            Copy-Item -Recurse -Path "$($mounted.Path)\*" -Destination $Destination
                            $null = Dismount-WindowsImage -Path $mountPoint -Discard
                        }
                        catch {
                            log_e "Unable to extract patch from $mountPoint"
                            # log_e $_.ScriptStackTrace
                            log_e $_
                        }
                        finally {
                            if(Test-Path -Path $mountPoint){
                                if(IsElevated){
                                    if($mountPoint -in $(Get-WindowsImage -Mounted).Path){
                                        Dismount-WindowsImage -Path $mountPoint -Discard
                                    }
                                }
                                Remove-Item $mountPoint -Recurse
                            }
                            Remove-Item -Path $tempWim
                        }
                    }
                    else{
                        ParseWim -Wim $Patch -Destination $Destination
                    }
                }
                default{
                    throw("Provided file is not a valid patch file.")
                }
            }
            
            $cabFiles = Get-ChildItem -Path $Destination -Filter *.cab
            $psf = Get-ChildItem -Path $Destination -Filter *.psf
            
            if($psf){
                log_s "PSF file [$($psf.Name)] found."
                $deploymentCab = $cabFiles.Where({$_.Name -eq "DesktopDeployment.cab"})
                if(!(Test-Path $deploymentCab.FullName)){
                    log_e "Unable to find DesktopDeployment.cab"
                    exit
                }
                else{
                    log_s "Found DesktopDeployment.cab"
                }

                # Expand and process PSF file
                try {
                    ExpandPSF -CAB $deploymentCab.FullName -Psf $psf.FullName -Destination $Destination
                }
                catch {
                    log_e "Unable to expand .psf file [$($psf.Name)]. Proceeding with CAB files expansion."
                    log_e $_
                    log_e $_.ScriptStackTrace
                    exit
                }
            }

            # Expand cab files
            try {
                foreach($cabFile in $cabFiles){
                    log_i "Expanding $cabFile"
                    if(!($cabFile.Name -eq "WSUSSCAN.cab") -or ($NoSSU -and $cabFile.Name -like "SSU-*" -or $cabFile.Name -like "DesktopDeployment*")){
                        $hash = Get-FileHash -Algorithm MD5 $cabFile.FullName
                        $tmpCabFile = Join-Path -ChildPath $($cabFile.BaseName + "-" + $hash.Hash.SubString(0, 5) + ".cab") -Path $cabFile.DirectoryName
                        Move-Item -Path $cabFile.FullName -Destination $tmpCabFile -Force -ErrorAction SilentlyContinue
                        $cabFile = $tmpCabFile
                        $null = Invoke-Expression "$expand -F:* $cabFile $Destination"
                        log_i "Moving $cabFile to $BIN"
                        Move-Item -Path $cabFile -Destination $BIN -Force -ErrorAction SilentlyContinue
                    }
                    else{
                        log_i "Moving $cabFile to $BIN"
                        Move-Item -Path $cabFile.FullName -Destination $BIN -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                log_e "Unable to expand extracted .cab files"
                log_e $_
                log_e $_.ScriptStackTrace
                exit
            }
        }
        else{
            log_e "Unable to read signature bytes from patch file."
        }
    }
    end{
        $fs.Dispose()
    }
}

function GetDeltaDll{
    param(
        [string]$CAB
    )
    # There should be a copy of this dll on the machine. Original script downloads a copy. Decided not to implement the DL
    $deltaDll = "C:\Windows\System32\msdelta.dll"
    if(Test-Path $CAB){
        $dir = $(Get-ChildItem $CAB).DirectoryName
        $tmp = Join-Path -Path $dir -ChildPath "UpdateCompression.dll"
        $null = Invoke-Expression "$expand -F:UpdateCompression.dll $CAB $dir"
        return $tmp
    }
    return $deltaDll
}

function ExpandPSF{
    param(
        [string]$CAB,
        [string]$Psf,
        [string]$Destination
    )
    begin{
        $system32 = Join-Path -Path $(Get-Item -Path $env:windir).FullName -ChildPath "system32"
        $expand = Join-Path -Path $system32 -ChildPath "expand.exe"
        if(-not (Test-Path $expand)){
            throw("Unable to find expand.exe")
        }
    }
    
    process{
        log_i "Parsing PSF file: $Psf"
        # Need to escape backslashes
        $deltaDll = $(GetDeltaDll $CAB).Replace("\", "\\")
        log_i "Using $deltaDll for delta compression APIs."
        # Check if Delta assembly is already loaded and FFI can be instantiated
        try{
            $null = [FFI.UpdateCompression]
        }
        catch{
            Add-Type -Name UpdateCompression -Namespace FFI -MemberDefinition @"
            [StructLayout(LayoutKind.Sequential)]
            public struct DELTA_INPUT {
                public IntPtr lpcStart;
                public IntPtr uSize;
                public int Editable;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct DELTA_OUTPUT {
                public IntPtr lpStart;
                public IntPtr uSize;
            }

            [DllImport("$deltaDll", SetLastError=true)]
            public static extern bool ApplyDeltaB(
                int ApplyFlags,
                ref DELTA_INPUT Source,
                ref DELTA_INPUT Delta,
                ref DELTA_OUTPUT lpTarget
            );
            
            [DllImport("$deltaDll")]
            public static extern bool DeltaFree(IntPtr Buffer);
"@
        }

        $stream = [System.IO.FileStream]::new($(Resolve-Path $Psf), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        # Read offset and size of manifest data
        $manifestOffset = ReadSize (Read $stream 0x28 4)
        $manifestLength = ReadSize (Read $stream 0x2c 4)

        log_i "Manifest offset: $("0x{0:x}" -f $manifestOffset) | size: $("0x{0:x}" -f $manifestLength) "
        
        # Read PA30 delta
        $manifestDelta = Read $stream $manifestOffset $manifestLength
        $manifestBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($manifestLength)
        $null = [Runtime.InteropServices.Marshal]::Copy($manifestDelta, 0, $manifestBuffer, $manifestLength)
        # [System.IO.File]::WriteAllBytes(".\data", $manifestDelta)

        $source = [FFI.UpdateCompression+DELTA_INPUT]::new()
        $delta = [FFI.UpdateCompression+DELTA_INPUT]::new()
        $target = [FFI.UpdateCompression+DELTA_OUTPUT]::new()
        $source.lpcStart = [System.IntPtr]::Zero
        $source.uSize = [System.IntPtr]::Zero
        $delta.lpcStart = $manifestBuffer
        $delta.uSize = [System.IntPtr]$manifestLength

        $res = [FFI.UpdateCompression]::ApplyDeltaB(0, [ref]$source, [ref]$delta, [ref]$target)
        $null = [Runtime.InteropServices.Marshal]::FreeHGlobal($manifestBuffer)
        # $res
        if(!$res){
            log_e "Failed to expand manifest data"
            exit
        }

        # Extract XML data
        $xmlBuff = [byte[]]::new($target.uSize)
        $null = [Runtime.InteropServices.Marshal]::Copy($target.lpStart, $xmlBuff, 0, $target.uSize)
        $null = [FFI.UpdateCompression]::DeltaFree($target.lpStart)
        $xml = [xml]([Text.Encoding]::UTF8.GetString($xmlBuff))
        $xml.Save($(Join-Path -Path $Destination -ChildPath "psf.xml"))
        if($xml.Container.Type -ne "PSF"){
            log_e "Manifest XML is invalid"
            exit
        }
        
        # Unpack patch
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $nodes = $xml.Container.Files.ChildNodes
        $childNodesCount = $xml.Container.Files.ChildNodes.Count
        $ctr = 0
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $elapsed = 1500
        foreach($node in $nodes){
            # Show progress
            $percent = [Math]::Round($($ctr / $childNodesCount * 100), 2)
            if($stopWatch.Elapsed.TotalMilliseconds -ge $elapsed){
                Write-Progress -PercentComplete $percent -Status "$ctr of $childNodesCount Files ($percent%)" -Activity "Unpacking $Psf"
                $stopWatch.Reset()
                $stopWatch.Start()
            }

            $nOffset = $node.Delta.Source.offset
            $nLength = $node.Delta.Source.length
            $nHash = $node.Delta.Source.Hash.Value.ToUpper()
            $nName = Normalize $node.Name
            
            try {
                $parent = [System.IO.Path]::GetDirectoryName($nName)
                if(!(Test-Path $parent)){
                    $null = [System.IO.Directory]::CreateDirectory($parent)
                }
                $patchData = Read $stream $nOffset $nLength
                $shaSum = ReadHexString $($sha256.ComputeHash($patchData))
                if($nHash -ne $shaSum){
                    log_e "Computed hash [$nHash] does not match expected hash [$shaSum] for $nName"
                }
                [System.IO.File]::WriteAllBytes($nName, $patchData)
            }
            catch [System.IO.DirectoryNotFoundException] {
                log_e "Unable to write $nName"
                log_e $_
                log_e $_.ScriptStackTrace
            }
            catch {
                log_e $_
            }
            
            $ctr += 1
        }
    }
    end{
        Write-Progress -Activity "Unpacking $Psf" -Completed
        $stream.Dispose()
    }

}

function Normalize{
    param(
        [string]$fileName
    )

    $split = $fileName.Split("\")
    $parent = $split[0]
    $destination = $JUNK
    $prefixes = @()

    # Determine destination and prefixes
    # switch ($fileName) {
    switch ($parent) {
        { $parent -match ".resources_" } { break }
        { [System.IO.Path]::GetExtension($parent) -in @(".manifest", ".cat", ".mum", ".wim") } { break }
        { [System.IO.Path]::GetExtension($parent) -in @(".cab", ".xml", ".msu", ".pkgProperties.txt", ".ini", ".psf") } {
            $destination = $BIN
            break
        }
        { $parent -eq "patch" }{
            $destination = $BIN
            break
        }
        { $parent.StartsWith("x86_") }{
            $destination = $x86
            $prefixes = @("x86_microsoft-windows-", "x86_")
            break
        }
        { $parent.StartsWith("amd64_") }{
            $destination = $x64
            $prefixes = @("amd64_microsoft-windows-", "amd64_")
            break
        }
        { $parent.StartsWith("wow64_") }{
            $destination = $WOW
            $prefixes = @("wow64_microsoft-windows-", "wow64_")
            break
        }
        { $parent.StartsWith("msil_") }{
            $destination = $MSIL
            $prefixes = @("msil_")
            break
        }
        
        
        Default {}
    }
    
    foreach($prefix in $prefixes){
        if($fileName.StartsWith($prefix)){
            $replaced = $parent.Replace($prefix, "")
            $name, $null, $version, $null = $replaced.Split("_")
            $split[0] = $($name + "_" + $version).Replace("..","_")
            $fileName = $split -join "\"
            break
        }
    }

    $normalized = Join-Path -Path $(Resolve-Path $destination) -ChildPath $fileName
    return $normalized
}

function IsElevated{
    $p = [security.principal.windowsidentity]::getcurrent()
    $u = [System.Security.Principal.WindowsPrincipal]::new($p)
    return $u.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function BytesToString{
    param(
        [byte[]]$bytes
    )
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function StringToBytes{
    param(
        [string]$str
    )
    return [Text.Encoding]::UTF8.GetBytes($str)
}

function log{
    param(
        [String]$prefix,
        [String]$message,
        [String]$color
    )
    Write-Host "[$prefix] $message" -ForegroundColor $color
}

function log_s{
    param(
        [String]$message
    )
    log "+" $message "Green"
}

function log_e{
    param(
        [String]$message
    )
    log "-" $message "Yellow"
}

function log_i{
    param(
        [String]$message
    )
    log "*" $message "DarkMagenta"
}

# ParseWim Section

class BaseClass{
    $size
    $offset
}
class ResourceHeader : BaseClass{
    ResourceHeader($stream, $readOffset){
        $data = Read $stream $readOffset 0x16
        $this.size = ReadSize $data[0..6]
        $this.offset = ReadValue $data[8..15]
    }
}

class MetaData{
     # 102 is the minimum size of the struct https://github.com/ebiggers/wimlib/blob/master/include/wimlib/dentry.h#L17
    $metadataEntryStructSz = 0x66
    $length
    $CreationTime
    $LastAccessTime
    $LastWriteTime
    $SHA1
    $FileName
    MetaData($stream, $readOffset){
        $data = Read $stream $readOffset $this.metadataEntryStructSz

        # Parse metadata record entry, first record is the root record which can be skipped
        $this.length = ReadSize $data[0..7]
        $this.CreationTime = ReadValue $data[40..47]
        $this.LastAccessTime = ReadValue $data[48..55]
        $this.LastWriteTime = ReadValue $data[56..63]
        $this.SHA1 = ReadHexString $data[64..83]
        $fileNameLength = ReadSize $data[100..101]
        $this.FileName = ConvertWideChar $(Read $stream ($readOffset + $this.metadataEntryStructSz) $fileNameLength)
    }
}

class Resource : BaseClass{
    $SHA1
    Resource($stream, $readOffset){
        $data = Read $stream $readOffset 0x32
        $this.size = ReadSize $data[16..23]
        $this.offset = ReadValue $data[8..15]
        $this.SHA1 = ReadHexString $data[30..$data.length]
    }
}

function ParseWim {
    param (
        [string]$Wim,
        [string]$Destination
    )
    begin{
        $WimPath = Resolve-Path $Wim
        $fs = [System.IO.FileStream]::new($WimPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $WimMagic = "MSWIM"
        $FLAG_HEADER_COMPRESSION = 0x2
        # Might not need to use these flags
        # $FLAG_HEADER_COMPRESS_XPRESS = 0x20000
        # $FLAG_HEADER_COMPRESS_LZX = 0x40000

        # Resource Flags
        # $RESHDR_FLAG_METADATA = 0x2
        # $RESHDR_FLAG_COMPRESSED = 0x4
    }
    process{
        $headerBytes = Read $fs 0 $WimMagic.Length
        $convertedBytes = BytesToString $headerBytes
        if($headerBytes.Length -ge 0){
            if($convertedBytes -eq $WimMagic){
                log_s "Magic bytes match WIM signature"
                $flags = [System.BitConverter]::ToUInt32((Read $fs 0x10 4), 0)
                if($flags -band $FLAG_HEADER_COMPRESSION){
                    log_e "WIM File is compressed. Unable to continue"
                    exit
                }
                log_s "WIM File is not compressed"
                $WimGUID = ReadHexString $(Read $fs 0x18 16)
                log_i "GUID: $WimGUID"

                $resourceHeaders = @{
                    rhOffsetTableHeader = $null
                    rhXmlDataHeader = $null
                    rhBootMetadataHeader = $null
                }

                $startIndex = 0
                $resourceStructSz = 0x32 # 50

                # Get resource files
                $resourceHeaders["rhOffsetTableHeader"] = [ResourceHeader]::new($fs, 0x30)
                log_s "Offset table at $("0x{0:x}" -f $resourceHeaders["rhOffsetTableHeader"].offset)"

                # Get XML Data
                $resourceHeaders["rhXmlDataHeader"] = [ResourceHeader]::new($fs, 0x48)
                # $xmlData = BytesToString $(Read $fs $resourceHeaders["rhXmlDataHeader"].offset $resourceHeaders["rhXmlDataHeader"].size)
                log_s "XML data at $("0x{0:x}" -f $resourceHeaders["rhXmlDataHeader"].offset)"

                # Get Metadata if available
                $resourceHeaders["rhBootMetadataHeader"] = [ResourceHeader]::new($fs, 0x60)
                if($resourceHeaders["rhBootMetadataHeader"].offset){
                    log_s "Boot metadata at $("0x{0:x}" -f $resourceHeaders["rhBootMetadataHeader"].offset)"
                }
                else{
                    log_i "Metadata not included in WIM File. Checking Resource files for metadata."
                    $resourceHeaders["rhBootMetadataHeader"] = [ResourceHeader]::new($fs, $resourceHeaders["rhOffsetTableHeader"].offset)
                    $startIndex = 1
                }

                $securityDataSz = ReadSize $(Read $fs $resourceHeaders["rhBootMetadataHeader"].offset 4)

                if($securityDataSz -le 8){
                    log_i "No boot metadata found. Using the first resource in the offset table."
                    $resourceHeaders["rhBootMetadataHeader"].offset += 0x78
                }

                $resources = [System.Collections.Generic.List[Resource]]::new()
                $metadataEntries = [System.Collections.Generic.List[MetaData]]::new()
                for($i = $startIndex; $i -lt $($resourceHeaders["rhOffsetTableHeader"].size / $resourceStructSz); $i++){
                    $resource = [Resource]::new($fs, ($resourceHeaders["rhOffsetTableHeader"].offset + ($i * 0x32)))
                    $metadataEntry = [MetaData]::new($fs, $resourceHeaders["rhBootMetadataHeader"].offset)
                    # Point to next metadata record
                    $resourceHeaders["rhBootMetadataHeader"].offset += $metadataEntry.length
                    $null =  $resources.Add($resource)
                    $null = $metadataEntries.Add($metadataEntry)
                }

                # Start reading and writing files to destination path
                if(!(Test-Path $Destination)){
                    $null = New-Item -Path $Destination -ItemType Directory
                }

                # Match metadata entry to resource entry, then write file to destination
                foreach($r in $resources){
                    $tmp = $metadataEntries.Where({$_.SHA1 -eq $r.SHA1})
                    log_s "Found file: $($tmp.FileName) [$($r.SHA1)]"
                    $p = $(Join-Path -Path $(Resolve-Path $Destination) -ChildPath $tmp.FileName)
                    $outputStream = [System.IO.File]::Create($p)
                    $null = $fs.Seek($r.offset, [System.IO.SeekOrigin]::Begin)
                    $chunk = 65536
                    $buffer = [byte[]]::new($chunk)

                    $counter = 0
                    $lastRead = $r.size % $chunk
                    while($counter -lt $r.size){
                        # Check if last read does not exceed file size
                        if(($r.size - $counter) -eq $lastRead){
                            $chunk = $lastRead
                        }
                        $read = $fs.Read($buffer, 0, $chunk)
                        $outputStream.Write($buffer, 0, $read)
                        $counter += $read
                    }
                    $outputStream.Close()
                    
                    [System.IO.File]::SetCreationTime($p, (GetDateTime $tmp.CreationTime))
                    [System.IO.File]::SetLastAccessTime($p, (GetDateTime $tmp.LastAccessTime))
                    [System.IO.File]::SetLastWriteTime($p, (GetDateTime $tmp.LastWriteTime))
                }
                # log_i $xmlData
            }
            else{
                log_e "File is not in WIM Format $headerBytes"
            }
        }
    }
    end{
        $fs.Dispose()
    }
}

function GetDateTime{
    param(
        [int64]$val
    )
    return [datetime]::FromFileTime($val)
}

function ReadHexString{
    param(
        [byte[]]$hexArr
    )
    return [System.BitConverter]::ToString($hexArr) -replace "-"
}

function ReadSize{
    param(
        [byte[]]$szArr
    )
    $tmp = [byte[]]::new(8)
    [array]::Copy($szArr, $tmp, $szArr.Length)
    return ReadValue $tmp
}

function ReadValue{
    param(
        [byte[]]$arr
    )
    return [System.BitConverter]::ToInt64($arr, 0)
}

function Read{
    param(
        [System.IO.FileStream]$stream,
        [long]$offset,
        [int64]$size
    )
    $readBytes = [byte[]]::new($size)
    $null = $stream.Seek($offset, [System.IO.SeekOrigin]::Begin)
    $counter = 0
    $chunk = 65536
    if($size -lt $chunk){
        $chunk = $size
    }

    while ($counter -lt $size) {
        $counter = $counter + $stream.Read($readBytes, 0, $readBytes.Length)
    }
    return $readBytes
}

function ConvertWideChar{
    param(
        [byte[]]$bytes
    )
    return [System.Text.Encoding]::Unicode.GetString($bytes)
}

function BytesToString{
    param(
        [byte[]]$bytes
    )
    # return [System.Text.Encoding]::ASCII.GetString($bytes)
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

Expand-Patch -Patch $Patch -Destination $Destination -NoSSU