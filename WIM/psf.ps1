param(
    [string]$CAB,
    [string]$PSF,
    [string]$Destination
)

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
        if($xml.Container.Type -ne "PSF"){
            log_e "Manifest XML is invalid"
            exit
        }
        
        # Unpack patch
        # $sha256 = [Security.Cryptography.HashAlgorithm]::Create("SHA256")
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $childNodesCount = $xml.Container.Files.ChildNodes.Count
        $ctr = 0
        foreach($node in $xml.Container.Files.ChildNodes){
            # Show progress
            $percent = [Math]::Round($($ctr / $childNodesCount * 100), 2)
            Write-Progress -PercentComplete $percent -Status "$ctr of $childNodesCount Files ($percent%)" -Activity "Unpacking $Psf" -SecondsRemaining -1

            $nOffset = $node.Delta.Source.offset
            $nLength = $node.Delta.Source.length
            $nHash = $node.Delta.Source.Hash.Value.ToUpper()
            $nName = Join-Path $Destination $node.Name            
            
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
            }
            catch {
                log_e $_
            }
            
            $ctr += 1
        }
    }
    end{
        $stream.Dispose()
    }

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

function ReadHexString{
    param(
        [byte[]]$hexArr
    )
    return [System.BitConverter]::ToString($hexArr) -replace "-"
}

ExpandPSF -CAB $CAB -Psf $Psf -Destination $Destination