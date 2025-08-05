# MSDOS (MS-DOS Executable) Class Reference

The MSDOS class provides analysis capabilities for MS-DOS executable files with MZ headers, including detection of extended executable formats and Rich signatures.

## Inheritance
* **Inherits from Binary class** - All Binary class functions are available with MSDOS prefix (e.g., `Binary.compareEP` → `MSDOS.compareEP`)

## Table of Contents
- [Extended Format Detection](#extended-format-detection)
- [DOS Stub Analysis](#dos-stub-analysis)
- [Rich Signature Support](#rich-signature-support)

## Extended Format Detection

MS-DOS files can contain extended executable formats. These functions detect the presence of newer formats embedded within MZ files.

### isLE()
**`bool isLE()`** - Check if the file contains a Linear Executable (LE) format.

**Returns:** `true` if LE format is detected, `false` otherwise

LE format was used by OS/2 and some Windows VxD drivers.

### isLX()
**`bool isLX()`** - Check if the file contains a Linear eXecutable (LX) format.

**Returns:** `true` if LX format is detected, `false` otherwise

LX format was used by OS/2 32-bit applications.

### isNE()
**`bool isNE()`** - Check if the file contains a New Executable (NE) format.

**Returns:** `true` if NE format is detected, `false` otherwise

NE format was used by Windows 16-bit applications.

### isPE()
**`bool isPE()`** - Check if the file contains a Portable Executable (PE) format.

**Returns:** `true` if PE format is detected, `false` otherwise

PE format is used by modern Windows applications.

**Examples:**
```javascript
// Detect extended executable types
if (MSDOS.isPE()) {
    sName = "PE executable";
} else if (MSDOS.isNE()) {
    sName = "NE executable";
} else if (MSDOS.isLE()) {
    sName = "LE executable";
} else if (MSDOS.isLX()) {
    sName = "LX executable";
} else {
    sName = "MS-DOS executable";
}
```

## DOS Stub Analysis

The DOS stub is the 16-bit code that runs when a newer executable format is run on plain MS-DOS.

### getDosStubOffset()
**`qint64 getDosStubOffset()`** - Get the file offset where the DOS stub begins.

**Returns:** File offset of the DOS stub

### getDosStubSize()
**`qint64 getDosStubSize()`** - Get the size of the DOS stub in bytes.

**Returns:** Size of the DOS stub

### isDosStubPresent()
**`bool isDosStubPresent()`** - Check if a DOS stub is present in the file.

**Returns:** `true` if DOS stub exists, `false` otherwise

**Examples:**
```javascript
if (MSDOS.isDosStubPresent()) {
    var stubSize = MSDOS.getDosStubSize();
    var stubOffset = MSDOS.getDosStubOffset();
    
    _log("DOS stub found: offset=" + stubOffset + ", size=" + stubSize);
    
    // Analyze stub content
    if (MSDOS.compare("'This program cannot be run in DOS mode'", stubOffset)) {
        sOptions = "standard stub";
    } else {
        sOptions = "custom stub";
    }
}
```

## Rich Signature Support

Rich signatures contain information about the Microsoft compiler and linker used to build the executable.

### isRichSignaturePresent()
**`bool isRichSignaturePresent()`** - Check if a Rich signature is present.

**Returns:** `true` if Rich signature exists, `false` otherwise

### getNumberOfRichIDs()
**`qint32 getNumberOfRichIDs()`** - Get the number of Rich signature entries.

**Returns:** Number of Rich signature entries

### isRichVersionPresent()
**`bool isRichVersionPresent(quint32 nVersion)`** - Check if a specific compiler version is present in Rich signature.

**Parameters:**
* `nVersion` - Compiler version to check for

**Returns:** `true` if version is found, `false` otherwise

### getRichVersion()
**`quint32 getRichVersion(qint32 nPosition)`** - Get the compiler version at a specific position.

**Parameters:**
* `nPosition` - Position index in Rich signature

**Returns:** Compiler version number

### getRichID()
**`quint32 getRichID(qint32 nPosition)`** - Get the compiler ID at a specific position.

**Parameters:**
* `nPosition` - Position index in Rich signature

**Returns:** Compiler ID

### getRichCount()
**`quint32 getRichCount(qint32 nPosition)`** - Get the object count at a specific position.

**Parameters:**
* `nPosition` - Position index in Rich signature

**Returns:** Object count for this compiler/version

**Examples:**
```javascript
if (MSDOS.isRichSignaturePresent()) {
    var richCount = MSDOS.getNumberOfRichIDs();
    _log("Rich signature found with " + richCount + " entries");
    
    // Analyze Rich signature entries
    for (var i = 0; i < richCount; i++) {
        var richID = MSDOS.getRichID(i);
        var richVersion = MSDOS.getRichVersion(i);
        var richObjCount = MSDOS.getRichCount(i);
        
        // Map common compiler IDs
        var compilerName = "";
        switch (richID) {
            case 0x5D: compilerName = "Visual C++ 6.0"; break;
            case 0x5E: compilerName = "Visual C++ .NET"; break;
            case 0x5F: compilerName = "Visual C++ 2003"; break;
            case 0x84: compilerName = "Visual C++ 2005"; break;
            case 0x85: compilerName = "Visual C++ 2008"; break;
            case 0x86: compilerName = "Visual C++ 2010"; break;
            case 0x87: compilerName = "Visual C++ 2012"; break;
            case 0x88: compilerName = "Visual C++ 2013"; break;
            default: compilerName = "Unknown (" + richID + ")"; break;
        }
        
        _log("Entry " + i + ": " + compilerName + " v" + richVersion + 
             " (" + richObjCount + " objects)");
    }
    
    // Check for specific Visual Studio versions
    if (MSDOS.isRichVersionPresent(0x86)) {
        sOptions = "Visual C++ 2010";
    }
}
```