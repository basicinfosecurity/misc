# WIM
Scripts to parse WIM files. Also includes a reworked version of [PatchExtract.ps1](https://gist.github.com/wumb0/306f97dc8376c6f53b9f9865f60b4fb5) with the WIM parsing implementation. Read the blog post: https://pleasedonthack.me/blog/At-the-WIM-of-Microsoft/

## Usage
### wim.ps1
```
PS C:\> .\wim.ps1 -Wim .\wim.msu
[+] Magic bytes match WIM signature
[+] WIM File is not compressed
[*] GUID: 35C3305ECFA83CE22B673A79518C202A
[+] Offset table at 0x30a2d304
[+] XML data at 0x30a2d494
[*] Metadata not included in WIM File. Checking Resource files for metadata.
[*] No boot metadata found. Using the first resource in the offset table.
[+] Found file: DesktopDeployment.cab [89E96B37CC2EE5E6017FF2AB03E399133C65C002]
[+] Found file: DesktopDeployment_x86.cab [0884E45A1E35D453368C0E6A730317122E92A10F]
[+] Found file: SSU-26100.3764-x64.cab [2D4713681EA1FB66172EB2DDB1F6BED5D447664B]
[+] Found file: Windows11.0-KB5055523-x64.psf [A343EE70DB22870629EE0BD9F4672D1EF047F077]
[+] Found file: Windows11.0-KB5055523-x64.wim [4C698B7BA1F2F690130D6220EAA998CECD9CCE00]
[+] Found file: onepackage.AggregatedMetadata.cab [757FB964F02D464DC6D9BFE4DDDE161F67DA6C27]
[+] Found file: wsusscan.cab [AA2799D8FC05E1CF64E8E4F0CC517F7FEF62EDAD]

...

PS C:\> ls .\parsed\


    Directory: C:\path\to\parsed


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          6/4/2025   2:31 pm        7089534 DesktopDeployment.cab
-a----          6/4/2025   2:31 pm        5731050 DesktopDeployment_x86.cab
-a----          6/4/2025   2:31 pm          21400 onepackage.AggregatedMetadata.cab
-a----          6/4/2025   2:31 pm       19567851 SSU-26100.3764-x64.cab
-a----          6/4/2025   2:32 pm      656630558 Windows11.0-KB5055523-x64.psf
-a----          6/4/2025   2:32 pm      126649987 Windows11.0-KB5055523-x64.wim
-a----          6/4/2025   2:31 pm         285400 wsusscan.cab

PS C:\> Get-FileHash -Algorithm SHA1 -Path .\parsed\* | ft -Wrap

Algorithm       Hash                                                    Path
---------       ----                                                    ----
SHA1            89E96B37CC2EE5E6017FF2AB03E399133C65C002                C:\path\to\parsed\DesktopDeployment.cab
SHA1            0884E45A1E35D453368C0E6A730317122E92A10F                C:\path\to\parsed\DesktopDeployment_x86.cab
SHA1            757FB964F02D464DC6D9BFE4DDDE161F67DA6C27                C:\path\to\parsed\onepackage.AggregatedMetadata.cab
SHA1            2D4713681EA1FB66172EB2DDB1F6BED5D447664B                C:\path\to\parsed\SSU-26100.3764-x64.cab
SHA1            A343EE70DB22870629EE0BD9F4672D1EF047F077                C:\path\to\parsed\Windows11.0-KB5055523-x64.psf
SHA1            4C698B7BA1F2F690130D6220EAA998CECD9CCE00                C:\path\to\parsed\Windows11.0-KB5055523-x64.wim
SHA1            AA2799D8FC05E1CF64E8E4F0CC517F7FEF62EDAD                C:\path\to\parsed\wsusscan.cab
```

### wim.py
```
python .\wim.py -h
[*] Start: 1761023282.7248747
usage: wim.py [-h] -w WIM [-d DESTINATION]

WIM Parser 0.1

options:
  -h, --help            show this help message and exit
  -w, --wim WIM         Path to WIM
  -d, --destination DESTINATION
                        Destination directory

...

python .\wim.py -w .\wim.msu
[*] Start: 1761023327.1751835
[+] Magic bytes match WIM signature
[+] WIM is not compressed.
[+] GUID: 35c3305ecfa83ce22b673a79518c202a
[+] Offset table at 0x30a2d304
[+] XML data at 0x30a2d494
[*] Metadata not included in WIM File. Checking Resource files for metadata.
[*] No boot metadata found. Using the first resource in the offset table.
[+] Found file: DesktopDeployment.cab [89e96b37cc2ee5e6017ff2ab03e399133c65c002]
[+] Found file: DesktopDeployment_x86.cab [0884e45a1e35d453368c0e6a730317122e92a10f]
[+] Found file: SSU-26100.3764-x64.cab [2d4713681ea1fb66172eb2ddb1f6bed5d447664b]
[+] Found file: Windows11.0-KB5055523-x64.psf [a343ee70db22870629ee0bd9f4672d1ef047f077]
[+] Found file: Windows11.0-KB5055523-x64.wim [4c698b7ba1f2f690130d6220eaa998cecd9cce00]
[+] Found file: onepackage.AggregatedMetadata.cab [757fb964f02d464dc6d9bfe4ddde161f67da6c27]
[+] Found file: wsusscan.cab [aa2799d8fc05e1cf64e8e4f0cc517f7fef62edad]
[+] Done: 0.8231863975524902.
```

# Expand-Patch.ps1
A rework of the [PatchExtract.ps1](https://gist.github.com/wumb0/306f97dc8376c6f53b9f9865f60b4fb5) with the WIM parsing implementation. Also includes some bug fixes and optimizations.
![demo](images/expand%20patch%201.PNG)

# ImHex Pattern
The included pattern file is mostly developed according to Microsoft's [whitepaper](https://www.microsoft.com/en-us/download/details.aspx?id=13096) and wimlib code. While tested with valid WIM files, the test cases were focused on understanding patch files distributed by Microsoft as WIM files. As such, not all uses cases were covered.
![imhex](images/imhex%202.PNG)
