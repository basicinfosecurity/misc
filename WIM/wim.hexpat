#pragma author Jerowin Santillan
#pragma description Microsoft Windows Imaging File Format (wim)
#pragma magic [4D 53 57 49 4D] @ 0x00

#define GUID_SIZE   16
// Algorithm is SHA1
#define HASH_SIZE   20

import std.io;
import std.array;
import std.mem;
import std.math;
import type.magic;
import type.size;
import type.time;
//import type.base;

bitfield Flags{
    bool FLAG_HEADER_RESERVED : 1;
    bool FLAG_HEADER_COMPRESSION : 1;
    bool FLAG_HEADER_READONLY : 1;
    bool FLAG_HEADER_SPANNED : 1;
    bool FLAG_HEADER_RESOURCE_ONLY : 1;
    bool FLAG_HEADER_METADATA_ONLY : 1;
    bool FLAG_HEADER_WRITE_IN_PROGRESS : 1;
    bool FLAG_HEADER_RP_FIX : 1;
    padding : 8;
    bool FLAG_HEADER_COMPRESS_RESERVED : 1;
    bool FLAG_HEADER_COMPRESS_XPRESS : 1;
    bool FLAG_HEADER_COMPRESS_LZX : 1;
    bool FLAG_HEADER_COMPRESS_LZMS : 1;
    padding : 12;
};

fn check_flags(Flags flags){
    if(flags.FLAG_HEADER_COMPRESSION){
        std::print("WIM file contains compressed resources.\n");
    }
    
    if(flags.FLAG_HEADER_READONLY){
        std::print("WIM file is read only.\n");
    }
    
    if(flags.FLAG_HEADER_SPANNED){
        std::print("WIM file is split into multiple files.\n");
    }
    
    if(flags.FLAG_HEADER_RESOURCE_ONLY){
        std::print("Blob table contains non-metadata blobs.\n");
    }
    
    if(flags.FLAG_HEADER_METADATA_ONLY){
        std::print("Blob table contains metadata blobs.\n");
    }
    
    if(flags.FLAG_HEADER_WRITE_IN_PROGRESS){
        std::print("WIM is currently being written to.\n");
    }
    
    if(flags.FLAG_HEADER_RP_FIX){
        std::print("Reparse point fixup flag set.\n");
    }
    
    if(flags.FLAG_HEADER_COMPRESS_XPRESS){
        std::print("Resources compressed with XPRESS.\n");
    }
    
    if(flags.FLAG_HEADER_COMPRESS_LZX){
        std::print("Resources compressed with LZX.\n");
    }
    
    if(flags.FLAG_HEADER_COMPRESS_LZMS){
        std::print("Resources compressed with LZMS.\n");
    }
    std::print("\n");
};

fn show_as_hex(u64 v){
    str r = std::format("0x{0:x}", v);
    return r;
};


bitfield Resource_Flags{
    bool RESHDR_FLAG_FREE : 1;
    bool RESHDR_FLAG_METADATA : 1;
    bool RESHDR_FLAG_COMPRESSED : 1;
    bool RESHDR_FLAG_SPANNED : 1;
    // Since type of ULONGLONG was used, fill rest with padding
    padding : 4;
};

struct RESHDR_DISK_SHORT {
    u8 sizebytes[7];
    Resource_Flags bFlags;
    u64 liOffset[[format("show_as_hex")]];
    u64 liOriginalSize;
};

fn check_lookup_table_flags(Resource_Flags flags){
    if(flags.RESHDR_FLAG_FREE){
        std::print("Resource is marked as FREE.\n");
    }
    
    else if(flags.RESHDR_FLAG_METADATA){
        std::print("Resource is a metadata resource.\n");
    }
    
    else if(flags.RESHDR_FLAG_COMPRESSED){
        std::print("Resource is compressed.\n");
    }
    
    else if(flags.RESHDR_FLAG_SPANNED){
        std::print("Resource is marked as SPANNED.\n");
    }
    
    else{
        std::print("Resource flags not set.\n");
    }
};

struct _RESHDR_DISK{
    RESHDR_DISK_SHORT wim_reshdr;
    //check_lookup_table_flags(wim_reshdr.bFlags);
    u16 usPartNumber;
    u32 dwRefCount;
    u8 bHash[HASH_SIZE];
};

struct integrity_table{
    u32 cbSize;
    u32 dwNumElements;
    u32 dwChunkSize;
    //u8 abHashList[dwNumElements];
    std::Array<std::Array<u8, HASH_SIZE>, dwNumElements> abHashList;
};

bitfield File_Attributes{
    FILE_ATTRIBUTE_READONLY : 1;
    FILE_ATTRIBUTE_HIDDEN : 1;
    FILE_ATTRIBUTE_SYSTEM : 1;
    padding : 1;
    FILE_ATTRIBUTE_DIRECTORY : 1;
    FILE_ATTRIBUTE_ARCHIVE : 1;
    FILE_ATTRIBUTE_DEVICE : 1;
    FILE_ATTRIBUTE_NORMAL : 1;
    FILE_ATTRIBUTE_TEMPORARY : 1;
    FILE_ATTRIBUTE_SPARSE_FILE : 1;
    FILE_ATTRIBUTE_REPARSE_POINT : 1;
    FILE_ATTRIBUTE_COMPRESSED : 1;
    FILE_ATTRIBUTE_OFFLINE : 1;
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED : 1;
    FILE_ATTRIBUTE_ENCRYPTED : 1;
    FILE_ATTRIBUTE_INTEGRITY_STREAM : 1;
    FILE_ATTRIBUTE_VIRTUAL : 1;
    padding : 12;
};


// Metadata Resource start
// Security Data
struct _SECURITYBLOCK_DISK{
    u32 dwTotalLength;
    u32 dwNumEntries;
    if(dwTotalLength > 8 && dwNumEntries > 0){
        u64 liEntryLength;
        u8 security_descriptors[dwNumEntries * liEntryLength];
    }
};

struct _DIRENTRY_substruct{
    u32 dwReparseTag;
    u32 dwReparseReserved;
};

union _DIRENTRY_union{
    _DIRENTRY_substruct substruct;
    u64 liHardLink;
};

using time_t = std::time::EpochTime [[format("format_unix_time")]];
using FILETIME = u64 [[format("format_windows_time")]];

fn format_unix_time(time_t t) {
    return std::time::format(std::time::to_local(t), "%c");
};

fn format_windows_time(FILETIME t) {
    return format_unix_time(std::time::filetime_to_unix(t));
};

struct _DIRENTRY{
    s64 liLength;
    //u32 dwAttributes;
    File_Attributes dwAttributes;
    u32 dwSecurityId;
    s64 liSubdirOffset;
    s64 liUnused1;
    s64 liUnused2;
    type::FILETIME liCreationTime[[format("format_windows_time")]];
    type::FILETIME liLastAccessTime[[format("format_windows_time")]];
    type::FILETIME liLastWriteTime[[format("format_windows_time")]];
    u8 bHash[HASH_SIZE];
    u32 unkown_padding;
    //padding[4];
    _DIRENTRY_union deUnion;
    u16 wStreams;
    u16 wShortNameLength;
    u16 wFileNameLength;
    if(wFileNameLength == 0){
        char16 FileName[1];
    }
    else{
        char16 FileName[wFileNameLength / 2];
        padding[liLength - sizeof(this) - wFileNameLength];
    }
    if(dwAttributes.FILE_ATTRIBUTE_DIRECTORY){
        padding[8];
    }
    //padding[8];
};

fn bytes_to_int(auto arr, u8 size){
    u64 intValue = 0;
    for(u8 i = 0, i < size, i += 1){
        intValue += arr[i] << (8 * i);
    }
    //std::print("intValue {}", intValue);
    return intValue;
};

/*
struct metadata_resource{
    if(!parent.flags.FLAG_HEADER_COMPRESSION){
        _SECURITYBLOCK_DISK security_data;
        _DIRENTRY entries[(parent.rhOffsetTable.liOriginalSize/sizeof(_RESHDR_DISK))] @ $;
    }
    else{    
        u8 metadata_compressed[bytes_to_int(parent.rhBootMetadata.sizebytes, 7)];
    }    
};
*/

struct metadata_resource{
    _SECURITYBLOCK_DISK security_data;
    _DIRENTRY entries[(parent.rhOffsetTable.liOriginalSize/sizeof(_RESHDR_DISK))] @ $;   
};

fn check_metadata_flag(_RESHDR_DISK resources){
    u8 size = sizeof(resources);
    for(u8 i = 0, i < size, i += 1){
        if(resources[i].wim_reshdr.bFlags.RESHDR_FLAG_METADATA){
            return i;
        }
    }
    return 0;
};

// https://github.com/ebiggers/wimlib/blob/master/include/wimlib/header.h#L124
struct WIMHeader {
    type::Magic<"MSWIM\x00\x00\x00"> ImageTag;
    type::Size32 cbSize;
    u32 dwVersion;
    Flags flags;
    check_flags(flags);
    type::Size32 dwCompressionSize;
    // https://github.com/ebiggers/wimlib/blob/master/include/wimlib/guid.h#L14
    u8 gWIMGuid[GUID_SIZE];
    //type::Hex<u8> gWIMGuid[GUID_SIZE];
    u16 usPartNumber;
    u16 usTotalParts;
    u32 dwImageCount;
    // Lookup Table Header
    RESHDR_DISK_SHORT rhOffsetTable;
    RESHDR_DISK_SHORT rhXmlData;
    RESHDR_DISK_SHORT rhBootMetadata;
    u32 dwBootIndex;
    RESHDR_DISK_SHORT rhIntegrity;
    u8 bUnused[60];
    
    _RESHDR_DISK FileResources[(rhOffsetTable.liOriginalSize/sizeof(_RESHDR_DISK))] @ rhOffsetTable.liOffset;
    char xml_data[rhXmlData.liOriginalSize] @ rhXmlData.liOffset;
    if(rhBootMetadata.liOffset > 0){
        if(rhBootMetadata.bFlags.RESHDR_FLAG_COMPRESSED){
            u8 boot_metadata_compressed[bytes_to_int(rhBootMetadata.sizebytes, 7)] @ rhBootMetadata.liOffset;
        }
        else{
            metadata_resource boot_metadata @ rhBootMetadata.liOffset;
        }
    }
    else{
        // MS Behavior: first resource is usually the metadata file.
        // But the metadata can be on any resource index.
        if(!FileResources[check_metadata_flag(FileResources)].wim_reshdr.bFlags.RESHDR_FLAG_COMPRESSED){
            metadata_resource boot_metadata @ FileResources[check_metadata_flag(FileResources)].wim_reshdr.liOffset;
        }
        else{
            u8 boot_metadata_compressed[bytes_to_int(FileResources[check_metadata_flag(FileResources)].wim_reshdr.sizebytes, 7)] @ FileResources[check_metadata_flag(FileResources)].wim_reshdr.liOffset;
        }
    }
    if(rhIntegrity.liOffset > 0){
        integrity_table integrity_table @ rhIntegrity.liOffset;
    }
};

WIMHeader header @ 0x00;

fn get_hex(auto x, u8 sz){
    str s = "";
    for(u8 i = 0, i < sz, i += 1){
        s = s + std::format("{:02X}", x[i]);
    }
    return s;
};
//std::print("WIM GUID: {}", get_hex(header.gWIMGuid, GUID_SIZE));
std::print("WIM GUID: {}\n", get_hex(header.gWIMGuid, sizeof(header.gWIMGuid)));