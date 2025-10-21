from argparse import ArgumentParser
from pathlib import Path
from ctypes import wintypes, WinDLL, WinError, get_last_error, byref
import time

# Header flag
FLAG_HEADER_COMPRESSION = 0x2
GUID_SIZE = 16
# SHA1
HASH_SIZE = 20

# Constants for CreateFile API
FILE_WRITE_ATTRIBUTES = 0x100
OPEN_EXISTING = 0x3
FILE_ATTRIBUTE_NORMAL = 0x80

class WIMHeader:
    def __init__(self):
        self.magic = b"MSWIM\x00\x00\x00"

class BaseClass:
    def __init__(self):
        self.size = None
        self.offset = None
    
    def __repr__(self):
        return f"{self.__class__}: offset: {hex(self.offset)} | size: {self.size}"

class ResourceHeader(BaseClass):
    def __init__(self, stream, offset):
        self.stream = stream
        self.size, offset = readSize(self.stream, offset)
        self.offset, _ = read64(self.stream, offset)

class MetaData:
    def __init__(self, stream, offset):
        # 102 is the minimum size of the struct https://github.com/ebiggers/wimlib/blob/master/include/wimlib/dentry.h#L17
        metadataEntryStructSz = 0x66
        tmpOffset = offset
        self.stream = stream
        self.length, offset = read64(self.stream, offset)
        self.timestamps = {}
        self.timestamps["CreationTime"], offset = read64(self.stream, offset + 0x20)
        self.timestamps["LastAccessTime"], offset = read64(self.stream, offset)
        self.timestamps["LastWriteTime"], offset = read64(self.stream, offset)
        sha1, offset = read2(self.stream, offset, HASH_SIZE)
        self.sha1 = sha1.hex()
        fileNameLength, _ = readSize(self.stream, offset + 0x10, 2)
        FileName, _ = read2(self.stream, tmpOffset + metadataEntryStructSz, fileNameLength)
        self.FileName = FileName.decode("utf16")

class Resource(BaseClass):
    def __init__(self, stream, offset):
        self.stream = stream
        self.offset, offset = read64(self.stream, offset)
        self.size, offset = readSize(self.stream, offset)
        sha1, _ = read2(self.stream, offset + 0x6, HASH_SIZE)
        self.sha1 = sha1.hex()

class WIM:
    def __init__(self, path, destination):
        self.path = path
        self.destination = destination
        self.stream = open(path, "rb")
        self.kernel32 = WinDLL("kernel32", use_last_error=True)
    
    def parse_wim(self):
        self.header = WIMHeader()
        magic, offset = read2(self.stream, offset = 0, chunk = len(self.header.magic))
        assert magic == self.header.magic, "Magic bytes do not match WIM file"
        log_s("Magic bytes match WIM signature")
        
        offset += 0x8
        flags, offset = read2(self.stream, offset, 4)
        # If there are compressed resources, exit (?)
        assert (read_bytes_le(flags) & FLAG_HEADER_COMPRESSION) != FLAG_HEADER_COMPRESSION, "WIM Resources are compressed."
        log_s("WIM is not compressed.")

        offset += 0x4
        guid, offset = read2(self.stream, offset, GUID_SIZE)
        log_s("GUID: " + guid.hex())

        resourceHeaders = {
            "rhOffsetTableHeader": None,
            "rhXmlDataHeader": None,
            "rhBootMetadataHeader": None
        }

        resourceHeaders["rhOffsetTableHeader"] = ResourceHeader(self.stream, 0x30)
        log_s(f"Offset table at {hex(resourceHeaders["rhOffsetTableHeader"].offset)}")

        resourceHeaders["rhXmlDataHeader"] = ResourceHeader(self.stream, 0x48)
        xmlData, _ = read2(self.stream, resourceHeaders["rhXmlDataHeader"].offset, resourceHeaders["rhXmlDataHeader"].size)
        log_s(f"XML data at {hex(resourceHeaders["rhXmlDataHeader"].offset)}")

        startIndex = 0
        resourceStructSz = 0x32
        offset += 0x8

        resourceHeaders["rhBootMetadataHeader"] = ResourceHeader(self.stream, 0x60)
        if(resourceHeaders["rhBootMetadataHeader"].offset > 0):
            log_s(f"Boot metadata at {hex(resourceHeaders["rhBootMetadataHeader"].offset)}")
        else:
            log_i("Metadata not included in WIM File. Checking Resource files for metadata.")
            resourceHeaders["rhBootMetadataHeader"] = ResourceHeader(self.stream, resourceHeaders["rhOffsetTableHeader"].offset)
            startIndex = 1
        
        securityDataSz, _ = read2(self.stream, resourceHeaders["rhBootMetadataHeader"].offset, 4)
        if(read_bytes_le(securityDataSz) <= 8):
            log_i("No boot metadata found. Using the first resource in the offset table.")
            resourceHeaders["rhBootMetadataHeader"].offset += 0x78
        
        resources = []
        metadataEntries = []

        for i in range(startIndex, (resourceHeaders["rhOffsetTableHeader"].size // resourceStructSz)):
            # Read Offset table entry
            resource = Resource(self.stream, (resourceHeaders["rhOffsetTableHeader"].offset + (i * resourceStructSz)) + 0x8)

            # Read metadata entry
            metadataEntry = MetaData(self.stream, resourceHeaders["rhBootMetadataHeader"].offset)
            resourceHeaders["rhBootMetadataHeader"].offset += metadataEntry.length
            resources.append(resource)
            metadataEntries.append(metadataEntry)
        
        destination = Path(self.destination)
        if not destination.exists():
            destination.mkdir()
        
        for r in resources:
            tmp = [m for m in metadataEntries if m.sha1 == r.sha1][0]
            log_s(f"Found file: {tmp.FileName} [{tmp.sha1}]")
            p = Path(destination / tmp.FileName)
            with p.open("wb") as outputStream:
                for readChunk in read_chunks(self.stream, r.size, r.offset):
                    outputStream.write(readChunk)
                outputStream.close()
                self.setTimes(tmp, str(p))
        
    
    # Use pinvoke to set the timestamps. This part can be skipped and is not that important
    # but thought to include for completeness
    def setTimes(self, entry, path = None):
        hFile = self.kernel32.CreateFileW(path, FILE_WRITE_ATTRIBUTES, None, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if hFile == -1:
            log_e(f"Unable to open {path}: {WinError(get_last_error())}")
            return
        timestamps = {}
        for k in ["CreationTime", "LastAccessTime", "LastWriteTime"]:
            t = entry.timestamps[k]
            dwHighDateTime = t >> 32
            dwLowDateTime = t & 0xffffffff
            ts = wintypes.FILETIME(dwLowDateTime, dwHighDateTime)
            timestamps[k] = ts
        
        if not wintypes.BOOL(self.kernel32.SetFileTime(hFile, byref(timestamps["CreationTime"]), byref(timestamps["LastAccessTime"]), byref(timestamps["LastWriteTime"]))):
            log_e(f"Unable to set timestamps: {WinError(get_last_error())}")
            return
        
        if not wintypes.BOOL(self.kernel32.CloseHandle(hFile)):
            log_e(f"Unable to close handle to file: {WinError(get_last_error())}")
            return

def log(prefix, message):
    print(f"[{prefix}] {message}")

def log_s(message):
    log("+", message)

def log_i(message):
    log("*", message)

def log_e(message):
    log("-", message)

def readSize(stream, offset, size = 0x7):
    data, offset = read2(stream, offset, size)
    return read_bytes_le(data), (offset + (0x8 - size))
    
def read64(stream, offset):
    data, offset = read2(stream, offset, 0x8)
    return read_bytes_le(data), offset
    
def read2(stream, offset, chunk):
    stream.seek(offset)
    return read(stream, chunk), offset + chunk
    
# Don't want to write the word "stream" too much
def read(stream, chunk):
    return stream.read(chunk)
    
def read_bytes_le(b):
    return int.from_bytes(b, "little")
    
def read_chunks(stream, size, offset=0, chunk=65536):
    stream.seek(offset)
    counter = 0
    lastRead = size % chunk
    while counter < size:
        if((size - counter) == lastRead):
            chunk = lastRead
        data = read(stream, chunk)
        if not data:
            break
        counter += chunk
        yield data

def main():
    start = time.time()
    log_i(f"Start: {start}")
    version = 0.1
    description = f"WIM Parser {version}"
    parser = ArgumentParser(description=description)
    parser.add_argument("-w", "--wim", help="Path to WIM", required=True)
    parser.add_argument("-d", "--destination", help="Destination directory", default="parsed")
    args = vars(parser.parse_args())

    wimPath = args.get("wim")
    destination = args.get("destination")

    try:
        wim = WIM(wimPath, destination)
        wim.parse_wim()
    except Exception as e:
        raise e
    finally:
        end = time.time()
        # log_s("Done.")
        log_s(f"Done: {end - start}.")

if __name__ == "__main__":
    exit(main())