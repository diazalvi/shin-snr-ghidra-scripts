# shin-snr-ghidra-scripts

Auxiliary support generated ghidra scripts to help with RE

* **AnalyzeSigsetjmpLandingPads.java** - Analyze sigsetjmp/longjmp code at the end of functions that handles the frame unwinding while doing exception handling (removes clutter from Xrefs) 
* **AnnotateBoostFunction.py** - Analyzes boost::function creation sites and creates types, renames functions, determines vtables, gets the type information from C++ mangled types  and add comments to better understand function and avoid reversing tedious templated code.
* **PatchExtswAfterLwz.py** - Patches out extsw instructions extending PowerPC 32-bit pointers into 64-bit registers that can confuse the decompiler
* **Patchrldiclzext32.java** - Patches out uses of rldicl to clamp pointers to 32bits that can make decompiler lose track

