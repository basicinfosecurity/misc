# Get-AsrRules
A powershell script to pull ASR rules from Windows Defender. This is a translation of [HackingLZ's](https://github.com/HackingLZ) [script](https://gist.github.com/HackingLZ/65f289b8b0b9c8c3a675aa26c06dfe09) and [Matt Graeber's](https://github.com/mattifestation) [script](https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866).

## Why?
I wanted to study the structure of the VDM file and how to extract the compiled lua scripts which contain the ASR details.

## Would you recommend using this script?
No.

It is horribly inefficient: it is computationally intensive, resource expensive and slow. The python script runs circles around this implementation, this after many attempts to optimize and refactor (which are glaringly apparent upon skimming the code). I urge you to use the python script instead of this one. This script might be viable as a last resort but should serve primarily as an educational toy for the curious. To give some idea of how inefficient it is, it is able to decompress the VDM file, extract the scripts and decompile them within 3 to 5 minutes. The python script completes the same tasks in under a minute.

## Usage
```
# Set the path of the decompiler via environment variable
$env:LUADEC = ".\luadec.exe" or
export LUADEC="./luadec"

# Decompress a VDM, then extract and decompile the compiled scripts
Get-AsrRules -Decompile -OutputPath dump -ExtractedVDM 123.abc -VDM extracted/mpasbase.vdm

# Pull and decompile scripts
Get-AsrRules -Decompile -ExtractedVDM 123.abc -OutputPath dump
```

## References
* Python script from which it was (mostly) based on: https://gist.github.com/HackingLZ/65f289b8b0b9c8c3a675aa26c06dfe09 and https://gist.github.com/mattifestation/3af5a472e11b7e135273e71cb5fed866
* Lua decompilers:
    * https://github.com/viruscamp/luadec
    * https://sourceforge.net/projects/unluac/
* Research from where this was based on:
    * https://github.com/commial/experiments/tree/master/windows-defender/VDM
    * https://github.com/taviso/loadlibrary/tree/master/engine
    * https://github.com/hfiref0x/WDExtract
    * Information on the VDM files: https://i.blackhat.com/BH-US-23/Presentations/US-23-Tomer-Defender-Pretender-final.pdf

## Additional Notes
### luadec
The windows port of the project does not seem to work out of the box. It will likely complain ```bad header in precompiled chunk```. Inspecting this with a debugger will reveal that the header sigs do not match. This is true regardless which environment where the compiled file was extracted in. However, the *nix port does not seem to have this issue. The user is encouraged to run this in a *nix environment. Or use another decompiler such as ```unluac```.