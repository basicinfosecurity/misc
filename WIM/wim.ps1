param(
    [string]$Wim,
    [string]$Destination = "parsed"
)


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

function Parse-Wim {
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
        $FLAG_HEADER_COMPRESS_XPRESS = 0x20000
        $FLAG_HEADER_COMPRESS_LZX = 0x40000

        # Resource Flags
        $RESHDR_FLAG_METADATA = 0x2
        $RESHDR_FLAG_COMPRESSED = 0x4
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
                $xmlData = BytesToString $(Read $fs $resourceHeaders["rhXmlDataHeader"].offset $resourceHeaders["rhXmlDataHeader"].size)
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

Parse-Wim -Wim $Wim -Destination $Destination