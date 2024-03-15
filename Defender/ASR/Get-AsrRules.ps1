<#
    .Description
    Get-AsrRules is a script capable of decompressing VDM files, extracting compiled LUA scripts and decompiling them (with an external decompiler)
    .Parameter VDM
    The path to the VDM File (mpasbase.vdm)
    .Parameter OutputPath
    The path to store the extracted compiled (and decompiled) LUA files
    .Parameter ExtractedVDM
    This will be the name of the decompressed VDM file. Defaults to extracted.xyz.
    .Parameter Decompile
    Include this flag to decompile the LUAC file after it is extracted. Set the LUADEC environment variable to the path of the decompiler before running the script.
    .SYNOPSIS
    Get-AsrRules is a script for extracting ASR rules from VDM files
    .EXAMPLE
    Get-AsrRules -Decompile -OutputPath dump -ExtractedVDM 123.abc -VDM extracted/mpasbase.vdm
    .EXAMPLE
    Get-AsrRules -Decompile -ExtractedVDM 123.abc -OutputPath dump
#>

function Get-AsrRules{
    # https://gist.github.com/HackingLZ/65f289b8b0b9c8c3a675aa26c06dfe09
    # https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866
    # https://github.com/viruscamp/luadec
    # https://github.com/commial/experiments/tree/master/windows-defender/VDM
    param(
        [string]$VDM,
        [string]$OutputPath,
        [string]$ExtractedVDM = "extracted.xyz",
        [switch]$Decompile
    )
    begin{
        $OutputPath = Join-Path $(Get-Location) $OutputPath
        $outFile = $ExtractedVDM
    }

    process{
        try{
            if("VDM" -in $PSBoundParameters.Keys){
                $vdmBytes = [IO.File]::ReadAllBytes((Get-Item $VDM).FullName)
                [string]$str = Get-DecodedVdm $vdmBytes
                if(-not $str.Substring(0, 2).Equals("MZ")){
                    throw [System.IO.IOException]::new("File is not a valid PE.")
                }
                $lookup = Get-DBSignature $str
                if(-not $lookup.Success){
                    throw [System.IO.IOException]::new("No DB header signature found.")
                }
                Write-Host "[+] Valid VDM File found."
                $processed = Expand-VDM $vdmBytes $lookup.Index $outFile
                if($processed){
                    Write-Host "[+] VDM Decompressed."
                }
                else{
                    throw [System.IO.FileNotFoundException]::new("Decompressed VDM file not found.")
                }
            }
            
            $ms = [IO.MemoryStream]::new([IO.File]::ReadAllBytes((Get-Item $outFile).FullName))
            $options = @{
                "output" = $OutputPath
                "decompile" = $Decompile
            }

            Convert-Scripts $options $ms
        }
        catch [System.IO.IOException]{
            Write-Host $_.Exception.Message -ForegroundColor "Red"
            Write-Host "[-] Something is wrong with the file: $($PSItem.ScriptStackTrace)"
        }
        catch [System.InvalidOperationException]{
            Write-Host $_.Exception.Message -ForegroundColor "Red"
            Write-Host "[-] Could not complete operation: $($PSItem.ScriptStackTrace)"
        }
        catch {
            Write-Host $_.Exception.Message -ForegroundColor "Red"
            Write-Host "[-] Something went wrong: $($PSItem.ScriptStackTrace)"
        }
        finally{
            # $processed.Dispose()
            $ms.Dispose()
            $ms.Close()
            [System.GC]::Collect()
        }
    }
}

function Get-DecodedVdm{
    param(
        $vdmBytes
    )
    $encoder = [Text.Encoding]::GetEncoding(28591)
    return $encoder.GetString($vdmBytes)
}

function Get-DBSignature{
    param(
        [string]$vdmStr
    )
    $dbSig = [regex]::new("RMDX")
    return $dbSig.Match($vdmStr)
}

function Expand-VDM {
    param (
        [byte[]]$vdm,
        [int]$index,
        [string]$outFile
    )
    $decompressed = $null
    $isDecompressed = $false
    $header = $vdm[$index..($index + 0x40 - 1)]
    $infoIndex = [System.BitConverter]::ToInt32($header, 0x18)
    $compressedDataSize = [System.BitConverter]::ToInt32($vdm, $index + $infoIndex)
    $compressedDataIndex = $index + $infoIndex + 8
    $compressed = $vdm[$compressedDataIndex..($compressedDataIndex + $compressedDataSize - 1)]
    try{
        Write-Host "[*] Decompressing..."
        $stream = [IO.MemoryStream]::new($compressed)
        # $decompressed = [IO.File]::Create("$PWD\$outFile")
        $decompressed = [IO.File]::Create($(Join-Path $(Get-Location) $outFile))
        $deflated = [IO.Compression.DeflateStream]::new($stream, [IO.Compression.CompressionMode]::Decompress)
        $deflated.CopyTo($decompressed)
        $isDecompressed = Test-Path $decompressed.Name
    }
    catch{
        Write-Host "[-] Unable to decompress VDM: $($PSItem.ScriptStackTrace)"
    }
    finally{
        $deflated.Dispose()
        $decompressed.Dispose()
        $stream.Dispose()
    }
    return $isDecompressed
}

function Convert-Scripts {
    param (
        [hashtable]$options,
        [IO.MemoryStream]$extractedStream
    )
    begin{
        if(-not (Test-Path $options.output)){
            Write-Host "[*] Creating Directory $(Split-Path -Leaf $options.output)."
           $null =  New-Item -Type Directory $options.output
        }
        $start = 0
        $luaq = [byte[]](0x1b, 0x4c,0x75, 0x61, 0x51) # b'\x1bLuaQ'
        $headerSig = [byte[]](0x1b, 0x4c, 0x75, 0x61, 0x51, 0x0, 0x1, 0x4, 0x8, 0x4, 0x8, 0x01) # b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'
        $binBytes = $extractedStream.ToArray()
        $scriptCtr = 1
        if($env:LUADEC){
            $luadec = $env:LUADEC
        }
    }
    process{
        function Find-Bytes {
            param (
                [byte[]]$binBytes,
                [int]$start,
                [byte[]]$patternBytes
            )
            process{
                [int]$end = $binBytes.Length - $patternBytes.Length
                [byte]$first = $patternBytes[0]
                [int]$i = [array]::IndexOf($binBytes, $first, $start)
                while(($i -ge 0) -and ($i -le $end)){
                    $segment = [byte[]]::new($patternBytes.Length)
                    [System.Buffer]::BlockCopy($binBytes, $i, $segment, 0, $patternBytes.Length)
                    if([System.Linq.Enumerable]::SequenceEqual($patternBytes, $segment)){
                        return $i
                    }
                    $i = [array]::IndexOf($binBytes, $first, $i + 1)
                }
                return -1
            }
        }

        $start = Find-Bytes $binBytes $start $luaq

        Write-Host "[*] Finding luac files."
        while($start -ne -1){
            $null = $extractedStream.Seek($start, [System.IO.SeekOrigin]::Begin)
            try{
                $outPath = Join-Path $options.output "$scriptCtr.luac"

                # Find start of luac file
                $buf = [byte[]]::new(12)
                $null = $extractedStream.Read($buf, 0, 12)
                $headerFound = [System.Linq.Enumerable]::SequenceEqual($buf, $headerSig)
                if($headerFound){
                    $func = [Lua]::new($extractedStream)
                    $export = $func.Export($true)
                    [IO.File]::WriteAllBytes($outPath, $export)
                    Clear-Variable -Name export
                    Clear-Variable -Name func
                }

                if($options.decompile -and $luadec){
                    $decompilePath = Join-Path $options.output "$scriptCtr.lua"
                    $pinfo = [System.Diagnostics.ProcessStartInfo]::new()
                    $pinfo.FileName = $luadec
                    $pinfo.RedirectStandardError = $true
                    $pinfo.RedirectStandardOutput = $true
                    $pinfo.UseShellExecute = $false
                    $pinfo.Arguments = $decompilePath
                    $pinfo.CreateNoWindow = $true
                    $proc = [System.Diagnostics.Process]::new()
                    $proc.StartInfo = $pinfo
                    $null = $proc.Start()
                    $result = [PSCustomObject]@{
                        stdout = $proc.StandardOutput.ReadToEnd()
                        stderr = $proc.StandardError.ReadToEnd()
                        ExitCode = $proc.ExitCode
                    }
                    # $proc.waitforexit()
                    $proc.WaitForExit()
                    $result.stdout | Out-File $decompilePath
                    # $result.stderr | Out-File ".\luadec_err.log" -Append -Encoding utf8
                    $proc.Dispose()
                }
                else{
                    throw [System.InvalidOperationException]::new("[!] Path to luadec binary invalid or not set. Please set via LUADEC environment variable.")
                }
            }
            catch [AssertException]{
                # Write-Host $_.Exception.Message -ForegroundColor "Red"
                # Write-Host $_.Exception.additionalData -ForegroundColor "Yellow"
                # Write-Host "[-] Assert failed: $($PSItem.ScriptStackTrace)"
                Write-Host "[-] Assert failed."
            }
            $start = Find-Bytes $binBytes ($start + 12) $luaq
            $scriptCtr++
        }
    }
    end{
        $ms.Dispose()
        $ms.Close()
        $extractedStream.Dispose()
        $extractedStream.Close()
    }
}

class Const {
    $value

    Const($value){
        $this.value = $value
    }
    [string]ToString(){
        return "<$($this.GetType()), $this.value>"
    }
}

class ConstNil : Const{
    ConstNil($value) : base($value) {}
}
class ConstByte : Const{
    ConstByte($value) : base($value) {}
}
class ConstNumber : Const{
    ConstNumber($value) : base($value) {}
}
class ConstString : Const{
    ConstString($value) : base($value) {}
}

class Lua{
    [IO.MemoryStream]$stream
    $nb_upvalues
    $nb_params
    $is_vararg
    $max_stacksize
    $nb_instr
    $instrs
    $nb_const
    $consts
    $funcs
    
    Lua($stream){
        $this.stream = $stream
        $this.Read_Header()
        $this.nb_upvalues = $this.Read_Byte()
        $this.nb_params = $this.Read_Byte()
        $this.is_vararg = $this.Read_Byte()
        $this.max_stacksize = $this.Read_Byte()

        $this.nb_instr = $this.Read_Int()
        $this.instrs = $this.Read_Bytes(4 * $this.nb_instr)
        $this.nb_const = $this.Read_Int()

        $this.Read_Consts()
        $this.Read_Funcs()

        $this.Read_Debug_Info()
    }

    [void]assert($a, $b){
        if($a.GetType() -eq [byte[]]){
            if(-not [System.Linq.Enumerable]::SequenceEqual($a, $b)){
                throw [AssertException]::new("Values are not the same.", "A: $a | B: $b")
            }
        }
        else{
            if($a -ne $b){
                throw [AssertException]::new("Values are not the same.", "A: $a | B: $b")
            }
        }
    }

    [void]Read_Header(){
        $src = $this.Read_Bytes(4)
        $this.assert($src, [byte[]]::new(4))
        $line_def = $this.Read_Bytes(4)
        $this.assert($line_def, [byte[]]::new(4))
        $lastline_def = $this.Read_Bytes(4)
        $this.assert($lastline_def, [byte[]]::new(4))
    }

    [byte]Read_Byte(){
        [byte]$b = $this.Read_Bytes(1)[0]
        return $b
    }
    [byte[]]Read_Bytes($size){
        $b = [byte[]]::new($size)
        $this.stream.Read($b, 0, $b.Length)
        return $b
    }

    [int]Read_Int(){
        return [System.BitConverter]::ToInt32($this.Read_Bytes(4), 0)
    }

    [void]Read_Consts(){
        $this.consts = [System.Collections.ArrayList]::new()
        $end = $this.nb_const - 1
        0..$end | &{
            process{
                    $cst_type = $this.Read_Byte()
                    if($cst_type -eq 4){
                        $length = $this.Read_Int()
                        $this.consts.Add([ConstString]::new($this.Read_Bytes($length)))
                    }
                    elseif ($cst_type -eq 3) {
                        # unpack <q should be equal roughly to Int64. Otherwise the numbers will be far too large when decompiled
                        $this.consts.Add([ConstNumber]::new($this.Get_Bytes([System.BitConverter]::ToInt64($this.Read_Bytes(8), 0))))
                    }
                    elseif ($cst_type -eq 1) {
                        $this.consts.Add([ConstByte]::new($this.Read_Byte()))
                    }
                    elseif ($cst_type -eq 0) {
                        $this.consts.Add([ConstNil]0)
                    }
                    else{
                        throw "Unimplemented."
                    }
            }
        }
    }

    [void]Read_Funcs(){
        $nb_func = $this.Read_Int()
        if($nb_func -gt 0){
            $this.funcs = @([Lua]::new($this.stream)) * $nb_func
        }
    }

    [void]Read_Debug_Info(){
        $src_line_positions = $this.Read_Int()
        $this.assert($src_line_positions, 0)
        $nb_locals = $this.Read_Int()
        $this.assert($nb_locals, 0)
        $nb_upvalues_local = $this.Read_Int()
        $this.assert($nb_upvalues_local, 0)
    }

    [byte[]]Export([bool]$root = $False){
        [byte[]]$header = if($root){$this.Export_Header()} else { [byte[]]0 }
        [byte[]]$vars = [byte[]]::new(0x10) + $this.nb_upvalues + $this.nb_params + $this.is_vararg + $this.max_stacksize + $this.Get_Bytes($this.nb_instr) + $this.instrs + $this.Get_Bytes($this.nb_const)
        [byte[]]$constants = foreach($cst in $this.consts){
            $this.Export_Const($cst)
        }
        [byte[]]$functionsLength = $this.Get_Bytes($this.funcs.Length)
        [byte[]]$functions = foreach($func in $this.funcs){
            $func.Export($False)
        }
        [byte[]]$padding = $this.Get_Bytes([int]0) * 3
        [byte[]]$out = $header + $vars + $constants + $functionsLength + $functions + $padding
        # Original function returns a sequence of bytes. Might just return as byte array
        return $out
    }

    [byte[]]Export_Header(){
        # b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00'
        return [byte[]](0x1b, 0x4c,0x75, 0x61, 0x51, 0x0, 0x1, 0x4, 0x8, 0x4, 0x8, 0x0)
    }

    [byte[]]Get_Bytes($value){
        return [System.BitConverter]::GetBytes($value)
    }

    [byte[]]Export_Const($cst){
        if($cst.GetType() -eq [ConstNil]){
            return [byte[]]0
        }
        elseif($cst.GetType() -eq [ConstByte]){
            return [byte[]](1, $cst.value)
        }
        elseif($cst.GetType() -eq [ConstNumber]) {
            # To emulate struct.pack('<d', val), need to retrieve the original integer value from byte array, then cast as double. Then get the correspoding byte array after cast
            return [byte[]]3 + $this.Get_Bytes([double][System.BitConverter]::ToInt64($cst.value, 0))
        }
        elseif($cst.GetType() -eq [ConstString]) {
            return [byte[]]4 + $this.Get_Bytes([uint64]$cst.value.Length) + $cst.value
        }
        return [byte[]]0
    }
}

class AssertException : System.Exception{
    [string]$additionalData
    AssertException($Message, $additionalData) : base($Message){
        $this.additionalData = $additionalData
    }
}