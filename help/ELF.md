# ELF (Executable and Linkable Format) Class Reference

The ELF class provides specialized analysis capabilities for Unix/Linux ELF files, including executables, shared libraries, and object files.

## Inheritance
* **Inherits from Binary class** - All Binary class functions are available with ELF prefix (e.g., `Binary.compareEP` → `ELF.compareEP`)

## Table of Contents
- [Section Management](#section-management)
- [Program Header Operations](#program-header-operations)
- [ELF Header Information](#elf-header-information)
- [String and Symbol Tables](#string-and-symbol-tables)
- [Library Dependencies](#library-dependencies)
- [General Properties](#general-properties)

## Section Management

### isSectionNamePresent()
**`bool isSectionNamePresent(QString sSectionName)`** - Check if a specific section exists in the ELF file.

**Parameters:**
* `sSectionName` - Name of the section to search for

**Returns:** `true` if section exists, `false` otherwise

**Examples:**
```javascript
if (ELF.isSectionNamePresent(".text")) {
    _log("Code section found");
}

if (ELF.isSectionNamePresent(".debug_info")) {
    sOptions += "debug symbols";
}
```

### getNumberOfSections()
**`quint32 getNumberOfSections()`** - Get the total number of sections in the ELF file.

**Returns:** Number of sections

### getSectionNumber()
**`qint32 getSectionNumber(QString sSectionName)`** - Get the index number of a specific section.

**Parameters:**
* `sSectionName` - Name of the section

**Returns:** Section index, or -1 if not found

### getSectionFileOffset()
**`quint64 getSectionFileOffset(quint32 nNumber)`** - Get the file offset of a section.

**Parameters:**
* `nNumber` - Section index number

**Returns:** File offset of the section

### getSectionFileSize()
**`quint64 getSectionFileSize(quint32 nNumber)`** - Get the size of a section.

**Parameters:**
* `nNumber` - Section index number

**Returns:** Size of the section in bytes

**Examples:**
```javascript
var textSection = ELF.getSectionNumber(".text");
if (textSection != -1) {
    var offset = ELF.getSectionFileOffset(textSection);
    var size = ELF.getSectionFileSize(textSection);
    _log("Text section: offset=" + offset + ", size=" + size);
}
```

## Program Header Operations

### getNumberOfPrograms()
**`quint32 getNumberOfPrograms()`** - Get the number of program headers.

**Returns:** Number of program headers

### getProgramFileOffset()
**`quint64 getProgramFileOffset(quint32 nNumber)`** - Get the file offset of a program header.

**Parameters:**
* `nNumber` - Program header index

**Returns:** File offset of the program header

### getProgramFileSize()
**`quint64 getProgramFileSize(quint32 nNumber)`** - Get the size of a program header.

**Parameters:**
* `nNumber` - Program header index

**Returns:** Size of the program header

## ELF Header Information

### getElfHeader_type()
**`quint16 getElfHeader_type()`** - Get the ELF file type from the header.

**Returns:** ELF type value (ET_EXEC=2, ET_DYN=3, ET_REL=1, etc.)

**Examples:**
```javascript
var elfType = ELF.getElfHeader_type();
switch (elfType) {
    case 1: sType = "Relocatable object"; break;
    case 2: sType = "Executable"; break;
    case 3: sType = "Shared library"; break;
    case 4: sType = "Core dump"; break;
}
```

### getElfHeader_machine()
**`quint16 getElfHeader_machine()`** - Get the target machine architecture.

**Returns:** Machine type value (EM_X86_64=62, EM_386=3, EM_ARM=40, etc.)

### getElfHeader_version()
**`quint32 getElfHeader_version()`** - Get the ELF version.

**Returns:** ELF version (typically 1 for current version)

### getElfHeader_entry()
**`quint64 getElfHeader_entry()`** - Get the entry point virtual address.

**Returns:** Entry point address

### getElfHeader_phoff()
**`quint64 getElfHeader_phoff()`** - Get the program header table file offset.

**Returns:** Program header table offset

### getElfHeader_shoff()
**`quint64 getElfHeader_shoff()`** - Get the section header table file offset.

**Returns:** Section header table offset

### getElfHeader_flags()
**`quint32 getElfHeader_flags()`** - Get processor-specific flags.

**Returns:** Flags value

### Header Size Functions

#### getElfHeader_ehsize()
**`quint16 getElfHeader_ehsize()`** - Get the ELF header size.

#### getElfHeader_phentsize()
**`quint16 getElfHeader_phentsize()`** - Get the program header entry size.

#### getElfHeader_phnum()
**`quint16 getElfHeader_phnum()`** - Get the number of program header entries.

#### getElfHeader_shentsize()
**`quint16 getElfHeader_shentsize()`** - Get the section header entry size.

#### getElfHeader_shnum()
**`quint16 getElfHeader_shnum()`** - Get the number of section header entries.

#### getElfHeader_shstrndx()
**`quint16 getElfHeader_shstrndx()`** - Get the section header string table index.

## String and Symbol Tables

### isStringInTablePresent()
**`bool isStringInTablePresent(QString sSectionName, QString sString)`** - Check if a string exists in a string table section.

**Parameters:**
* `sSectionName` - Name of the string table section
* `sString` - String to search for

**Returns:** `true` if string is found, `false` otherwise

**Examples:**
```javascript
if (ELF.isStringInTablePresent(".dynstr", "libc.so.6")) {
    _log("Links with glibc");
}

if (ELF.isStringInTablePresent(".shstrtab", ".debug_info")) {
    sOptions += "debug info";
}
```

## Library Dependencies

### isLibraryPresent()
**`bool isLibraryPresent(QString sLibraryName)`** - Check if a specific library is required by the ELF file.

**Parameters:**
* `sLibraryName` - Name of the library to check

**Returns:** `true` if library dependency exists, `false` otherwise

**Examples:**
```javascript
if (ELF.isLibraryPresent("libQt5Core.so.5")) {
    sFramework = "Qt 5";
    bDetected = true;
}

if (ELF.isLibraryPresent("libpthread.so.0")) {
    sOptions += "threading";
}
```

### getRunPath()
**`QString getRunPath()`** - Get the runtime library search path (RPATH/RUNPATH).

**Returns:** Runtime path string

**Examples:**
```javascript
var runPath = ELF.getRunPath();
if (runPath.length > 0) {
    _log("Runtime path: " + runPath);
}
```

## General Properties

### getGeneralOptions()
**`QString getGeneralOptions()`** - Get general file characteristics and options.

**Returns:** String containing general options and properties

**Examples:**
```javascript
var options = ELF.getGeneralOptions();
if (options.length > 0) {
    sOptions = options;
}

// Complete ELF analysis example
if (ELF.isLibraryPresent("libssl.so")) {
    sName = "OpenSSL application";
    
    if (ELF.isSectionNamePresent(".debug_info")) {
        sOptions = "with debug symbols";
    }
    
    var machineType = ELF.getElfHeader_machine();
    if (machineType == 62) {
        sOptions += ", x86-64";
    } else if (machineType == 3) {
        sOptions += ", i386";
    }
    
    bDetected = true;
}
```
