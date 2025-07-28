# PE (Portable Executable) Class Reference

The PE class provides specialized analysis capabilities for Windows Portable Executable (PE) files, including EXE, DLL, and SYS files.

## Inheritance
* **Inherits from Binary class** - All Binary class functions are available with PE prefix (e.g., `Binary.compareEP` → `PE.compareEP`)
* **Inherits from MSDOS class** - All MSDOS class functions are available with PE prefix (e.g., `MSDOS.isDosStubPresent` → `PE.isDosStubPresent`)

## Table of Contents
- [File Format Detection](#file-format-detection)
- [Section Management](#section-management)
- [Import Table Operations](#import-table-operations)
- [Export Table Operations](#export-table-operations)
- [Resource Management](#resource-management)
- [.NET Framework Support](#net-framework-support)
- [Version Information](#version-information)
- [Linker Information](#linker-information)
- [File Properties](#file-properties)
- [Advanced Analysis](#advanced-analysis)
- [Real-World PE Detection Examples](#real-world-pe-detection-examples)

## File Format Detection

### Basic PE Detection
**`bool isPEPlus()`** - Check if the file is PE32+ (64-bit) format.

**`bool isDll()`** - Check if the file is a Dynamic Link Library (DLL).

**`bool isDriver()`** - Check if the file is a device driver.

**`bool isConsole()`** - Check if the file is a console application.

### .NET Detection
**`bool isNET()`** - Check if the file contains .NET metadata.

**`QString getNETVersion()`** - Get the .NET Framework version.

**Examples:**
```javascript
if (PE.isNET()) {
    var netVersion = PE.getNETVersion();
    sInfo = ".NET " + netVersion;
    
    // Check for specific .NET features
    if (PE.isNetTypePresent("System.Windows.Forms", "Form")) {
        sFramework = "Windows Forms";
    } else if (PE.isNetTypePresent("System.Windows", "Window")) {
        sFramework = "WPF";
    }
}

if (PE.isDll()) {
    sType = "Dynamic Link Library";
    
    // Check if it's a .NET assembly
    if (PE.isNET()) {
        sType += " (.NET Assembly)";
    }
}

// Detailed architecture detection
if (PE.isPEPlus()) {
    sArchitecture = "x64 (PE32+)";
} else {
    sArchitecture = "x86 (PE32)";
}

// Check for specific PE characteristics
if (PE.isConsole()) {
    sSubsystem = "Console";
} else {
    sSubsystem = "Windows GUI";
}

if (PE.isDriver()) {
    sType = "Device Driver";
}
```

## Section Management

### Section Information
**`quint16 getNumberOfSections()`** - Get the total number of sections in the PE file.

**`QString getSectionName(quint32 nNumber)`** - Get the name of a specific section.

**`quint32 getSectionVirtualSize(quint32 nNumber)`** - Get the virtual size of a section.

**`quint32 getSectionVirtualAddress(quint32 nNumber)`** - Get the virtual address of a section.

**`quint32 getSectionFileSize(quint32 nNumber)`** - Get the raw data size of a section.

**`quint32 getSectionFileOffset(quint32 nNumber)`** - Get the file offset of a section.

**`quint32 getSectionCharacteristics(quint32 nNumber)`** - Get the characteristics flags of a section.

### Section Lookup and Validation
**`bool isSectionNamePresent(QString sSectionName)`** - Check if a section with the given name exists.

**`bool isSectionNamePresentExp(QString sSectionName)`** - Check if a section name exists using expression matching.

**`qint32 getSectionNumber(QString sSectionName)`** - Get the section number by name.

**`qint32 getSectionNumberExp(QString sSectionName)`** - Get the section number using expression matching.

**`QString getSectionNameCollision(QString sString1, QString sString2)`** - Check for section name collisions.

### Special Section Detection
**`qint32 getImportSection()`** - Get the section number containing the import table.

**`qint32 getExportSection()`** - Get the section number containing the export table.

**`qint32 getResourceSection()`** - Get the section number containing resources.

**`qint32 getEntryPointSection()`** - Get the section number containing the entry point.

**`qint32 getRelocsSection()`** - Get the section number containing relocations.

**`qint32 getTLSSection()`** - Get the section number containing Thread Local Storage.

**Examples:**
```javascript
var numSections = PE.getNumberOfSections();
for (var i = 0; i < numSections; i++) {
    var sectionName = PE.getSectionName(i);
    var virtualSize = PE.getSectionVirtualSize(i);
    
    if (sectionName == ".text") {
        var codeSize = virtualSize;
    }
}

if (PE.isSectionNamePresent(".rsrc")) {
    var resourceSection = PE.getSectionNumber(".rsrc");
}
```

## Import Table Operations

### Import Information
**`qint32 getNumberOfImports()`** - Get the number of imported libraries.

**`QString getImportLibraryName(quint32 nNumber)`** - Get the name of an imported library.

**`qint32 getNumberOfImportThunks(quint32 nNumber)`** - Get the number of functions imported from a library.

**`QString getImportFunctionName(quint32 nImport, quint32 nFunctionNumber)`** - Get the name of an imported function.

### Import Detection
**`bool isImportPresent()`** - Check if the file has an import table.

**`bool isLibraryPresent(QString sLibraryName, bool bCheckCase=false)`** - Check if a specific library is imported.

**`bool isLibraryFunctionPresent(QString sLibraryName, QString sFunctionName)`** - Check if a specific function is imported from a library.

### Import Hashing
**`quint32 getImportHash32()`** - Calculate 32-bit hash of import table.

**`quint64 getImportHash64()`** - Calculate 64-bit hash of import table.

**`bool isImportPositionHashPresent(qint32 nIndex, quint32 nHash)`** - Check if a specific import hash exists at position.

**Examples:**
```javascript
if (PE.isImportPresent()) {
    var numImports = PE.getNumberOfImports();
    
    for (var i = 0; i < numImports; i++) {
        var libName = PE.getImportLibraryName(i);
        
        if (libName.toLowerCase().includes("kernel32")) {
            var numFunctions = PE.getNumberOfImportThunks(i);
            
            // Analyze specific kernel32 functions
            for (var j = 0; j < numFunctions; j++) {
                var funcName = PE.getImportFunctionName(i, j);
                if (funcName == "VirtualProtect" || funcName == "VirtualAlloc") {
                    bMemoryManipulation = true;
                }
            }
        }
    }
}

// Check for specific libraries and functions
if (PE.isLibraryPresent("user32.dll")) {
    if (PE.isLibraryFunctionPresent("user32.dll", "MessageBoxA")) {
        bUsesMessageBox = true;
    }
    if (PE.isLibraryFunctionPresent("user32.dll", "SetWindowsHookExA")) {
        bUsesHooks = true;
    }
}

// Advanced import analysis for malware detection
if (PE.isLibraryPresent("ntdll.dll")) {
    var ntdllFunctions = ["NtCreateFile", "NtWriteFile", "NtReadFile"];
    var ntdllCount = 0;
    
    for (var i = 0; i < ntdllFunctions.length; i++) {
        if (PE.isLibraryFunctionPresent("ntdll.dll", ntdllFunctions[i])) {
            ntdllCount++;
        }
    }
    
    if (ntdllCount > 2) {
        bUsesNativAPI = true;
        sSuspiciousLevel = "High";
    }
}

// Calculate and analyze import hash
var importHash32 = PE.getImportHash32();
sImportHash = importHash32.toString(16).toUpperCase();
```

## Export Table Operations

### Export Information
**`bool isExportPresent()`** - Check if the file has an export table.

**`qint32 getNumberOfExportFunctions()`** - Get the number of exported functions.

**`QString getExportFunctionName(quint32 nNumber)`** - Get the name of an exported function.

### Export Detection
**`bool isExportFunctionPresent(QString sFunctionName)`** - Check if a specific function is exported.

**`bool isExportFunctionPresentExp(QString sFunctionName)`** - Check if an exported function exists using expression matching.

**Examples:**
```javascript
if (PE.isExportPresent()) {
    var numExports = PE.getNumberOfExportFunctions();
    
    for (var i = 0; i < numExports; i++) {
        var funcName = PE.getExportFunctionName(i);
        if (funcName.startsWith("Dll")) {
            sDllType = "Custom DLL";
        }
    }
}

if (PE.isExportFunctionPresent("DllMain")) {
    bHasDllMain = true;
}
```

## Resource Management

### Resource Information
**`bool isResourcesPresent()`** - Check if the file contains resources.

**`quint32 getNumberOfResources()`** - Get the total number of resources.

**`quint32 getResourceIdByNumber(quint32 nNumber)`** - Get the resource ID by index.

**`QString getResourceNameByNumber(quint32 nNumber)`** - Get the resource name by index.

**`qint64 getResourceOffsetByNumber(quint32 nNumber)`** - Get the file offset of a resource.

**`qint64 getResourceSizeByNumber(quint32 nNumber)`** - Get the size of a resource.

**`quint32 getResourceTypeByNumber(quint32 nNumber)`** - Get the type of a resource.

### Resource Lookup
**`qint64 getResourceNameOffset(QString sName)`** - Get the offset of a named resource.

**`bool isResourceNamePresent(QString sName)`** - Check if a named resource exists.

**`bool isResourceGroupNamePresent(QString sName)`** - Check if a resource group name exists.

**`bool isResourceGroupIdPresent(quint32 nID)`** - Check if a resource group ID exists.

**Examples:**
```javascript
if (PE.isResourcesPresent()) {
    var numResources = PE.getNumberOfResources();
    
    for (var i = 0; i < numResources; i++) {
        var resourceType = PE.getResourceTypeByNumber(i);
        var resourceSize = PE.getResourceSizeByNumber(i);
        
        if (resourceType == 16) { // RT_VERSION
            sHasVersionInfo = true;
        }
    }
}

if (PE.isResourceNamePresent("MANIFEST")) {
    var manifest = PE.getManifest();
}
```

## .NET Framework Support

### .NET String Detection
**`bool isNETStringPresent(QString sString)`** - Check if a .NET string is present.

**`bool isNETUnicodeStringPresent(QString sString)`** - Check if a .NET Unicode string is present.

**`bool isNetUStringPresent(QString sString)`** - Check if a .NET U-string is present.

### .NET Blob Analysis
**`qint64 findSignatureInBlob_NET(QString sSignature)`** - Find a signature in .NET blob.

**`bool isSignatureInBlobPresent_NET(QString sSignature)`** - Check if a signature exists in .NET blob.

**`bool compareEP_NET(QString sSignature, qint64 nOffset=0)`** - Compare signature at .NET entry point.

### .NET Metadata Analysis
**`bool isNetGlobalCctorPresent()`** - Check if .NET global constructor is present.

**`bool isNetTypePresent(QString sTypeNamespace, QString sTypeName)`** - Check if a .NET type exists.

**`bool isNetMethodPresent(QString sTypeNamespace, QString sTypeName, QString sMethodName)`** - Check if a .NET method exists.

**`bool isNetFieldPresent(QString sTypeNamespace, QString sTypeName, QString sFieldName)`** - Check if a .NET field exists.

**Examples:**
```javascript
if (PE.isNET()) {
    // String-based obfuscator detection
    var obfuscators = ["Confuser", "ConfuserEx", "Babel", "Dotfuscator", "SmartAssembly"];
    for (var i = 0; i < obfuscators.length; i++) {
        if (PE.isNETStringPresent(obfuscators[i])) {
            sObfuscator = obfuscators[i];
            break;
        }
    }
    
    // Framework capability detection
    if (PE.isNetTypePresent("System", "Console")) {
        bUsesConsole = true;
    }
    
    if (PE.isNetTypePresent("System.IO", "File")) {
        bUsesFileIO = true;
    }
    
    if (PE.isNetMethodPresent("System.IO", "File", "ReadAllText")) {
        bReadsFiles = true;
    }
    
    // Cryptography detection
    if (PE.isNetTypePresent("System.Security.Cryptography", "AES")) {
        bUsesCrypto = true;
        sCryptoType = "AES";
    }
    
    // Network capabilities
    if (PE.isNetTypePresent("System.Net", "WebClient")) {
        bNetworkCapable = true;
    }
    
    // Anti-debugging detection
    if (PE.isNetMethodPresent("System.Diagnostics", "Debugger", "IsAttached")) {
        bAntiDebug = true;
    }
    
    // Reflection usage (potential packer/obfuscator)
    if (PE.isNetTypePresent("System.Reflection", "Assembly")) {
        bUsesReflection = true;
    }
}
```

## Version Information

### File Version
**`QString getFileVersion()`** - Get the file version from version info.

**`QString getFileVersionMS()`** - Get the Microsoft-style file version.

**`QString getPEFileVersion(QString sFileName)`** - Get version of a specific PE file.

### Version String Information
**`QString getVersionStringInfo(QString sKey)`** - Get version string information by key.

**Common version keys:**
- `CompanyName`
- `FileDescription`
- `FileVersion`
- `ProductName`
- `ProductVersion`
- `LegalCopyright`
- `OriginalFilename`

**Examples:**
```javascript
var fileVersion = PE.getFileVersion();
var companyName = PE.getVersionStringInfo("CompanyName");
var productName = PE.getVersionStringInfo("ProductName");

if (companyName.includes("Microsoft")) {
    bMicrosoftFile = true;
}
```

## Linker Information

### Linker Version
**`quint8 getMajorLinkerVersion()`** - Get the major linker version.

**`quint8 getMinorLinkerVersion()`** - Get the minor linker version.

**`QString getCompilerVersion()`** - Get the compiler version information.

### Header Information
**`quint64 getImageFileHeader(QString sString)`** - Get IMAGE_FILE_HEADER field value.

**`quint64 getImageOptionalHeader(QString sString)`** - Get IMAGE_OPTIONAL_HEADER field value.

**`qint64 calculateSizeOfHeaders()`** - Calculate the total size of headers.

### Code and Data Sizes
**`quint32 getSizeOfCode()`** - Get the size of code section.

**`quint32 getSizeOfUninitializedData()`** - Get the size of uninitialized data.

**Examples:**
```javascript
var majorLinker = PE.getMajorLinkerVersion();
var minorLinker = PE.getMinorLinkerVersion();
var linkerVersion = majorLinker + "." + minorLinker;

var codeSize = PE.getSizeOfCode();
var headerSize = PE.calculateSizeOfHeaders();
```

## File Properties

### Security and Signing
**`bool isSignedFile()`** - Check if the file is digitally signed.

### Special Features
**`bool isTLSPresent()`** - Check if Thread Local Storage is present.

**`QString getManifest()`** - Get the embedded manifest content.

### General Options
**`QString getGeneralOptions()`** - Get general PE file options and characteristics.

**Examples:**
```javascript
if (PE.isSignedFile()) {
    sSecurity = "Digitally Signed";
}

if (PE.isTLSPresent()) {
    bUsesTLS = true;
}

var manifest = PE.getManifest();
if (manifest.includes("requireAdministrator")) {
    bRequiresAdmin = true;
}
```

## Advanced Analysis

### Hash Analysis
Functions for calculating and comparing import hashes for malware analysis and similarity detection.

### Metadata Inspection
Deep analysis of .NET metadata for understanding application structure and dependencies.

### Section Analysis
Detailed examination of PE sections for packing detection and code analysis.

### Resource Extraction
Access to embedded resources including version information, icons, and manifests.

## Real-World PE Detection Examples

This section contains practical examples from the DIE PE signature database showing how to use PE class methods for analyzing Windows executables.

### Packer Detection

#### UPX Packer Detection
```javascript
// UPX detection with import analysis
function detectUPX() {
    var nNumberOfFunctions = PE.getNumberOfImportThunks(0);
    
    if (nNumberOfFunctions > 1 && nNumberOfFunctions < 7) {
        if (PE.getSizeOfCode() && PE.getSizeOfUninitializedData() && 
            PE.getNumberOfSections() > 2) {
            
            var funcCounter = 0;
            
            // Check for typical UPX import functions
            if (PE.getImportFunctionName(0, 0) == "LoadLibraryA") {
                funcCounter++;
            }
            if (PE.getImportFunctionName(0, 1) == "GetProcAddress") {
                funcCounter++;
            }
            
            if (nNumberOfFunctions == 4) {
                if (PE.getImportFunctionName(0, 2) == "VirtualProtect") {
                    funcCounter++;
                }
                if (PE.getImportFunctionName(0, 3) == "ExitProcess") {
                    funcCounter++;
                }
            }
            
            if (funcCounter >= 2) {
                sName = "UPX";
                sType = "packer";
                bDetected = true;
            }
        }
    }
}
```

#### ASPack Packer Detection
```javascript
// ASPack detection with entry point pattern matching
function detectASPack() {
    var nOffset = PE.getEntryPointOffset();
    
    if (PE.compare("60E8000000005D81ED........B8........03C5", nOffset)) {
        sName = "ASPack";
        sVersion = "1.00b-1.07b";
        bDetected = true;
    } else if (PE.compare("60E8000000005D............BB........03DD", nOffset)) {
        sName = "ASPack";
        sVersion = "1.08.03";
        bDetected = true;
    } else if (PE.compare("60E870050000EB4C", nOffset)) {
        sName = "ASPack";
        sVersion = "2.000";
        bDetected = true;
    } else if (PE.compare("60E93D040000", nOffset)) {
        sName = "ASPack";
        sVersion = "2.11";
        bDetected = true;
    }
}
```

#### VMProtect Detection
```javascript
// VMProtect detection using section analysis
function detectVMProtect() {
    if (PE.isNET()) return; // Native files only
    
    var nNumberOfSections = PE.getNumberOfSections();
    
    for (var i = nNumberOfSections - 1; i >= 0; i--) {
        if (i == PE.getRelocsSection() || i == PE.getResourceSection()) {
            continue;
        }
        
        var sectionName = PE.getSectionName(i);
        
        if (i > 0 && sectionName == ".vmp0") {
            sName = "VMProtect";
            bDetected = true;
            break;
        } else if (i > 1 && sectionName.substr(sectionName.length - 1) == "1") {
            var sCollision = PE.getSectionNameCollision("0", "1");
            
            if (PE.isSectionNamePresent(sCollision + "1")) {
                sName = "VMProtect";
                bDetected = true;
                break;
            }
        }
    }
}
```

### Compiler Detection

#### Microsoft Visual C++ Detection
```javascript
// Comprehensive Microsoft compiler detection
function detectMicrosoftCompiler() {
    var linkerMajor = PE.getMajorLinkerVersion();
    var linkerMinor = PE.getMinorLinkerVersion();
    
    // Rich signature analysis for detailed version detection
    var richSignatureOffset = PE.findSignature(0, 0x1000, "52696368"); // "Rich"
    if (richSignatureOffset != -1) {
        sName = "Microsoft Visual C++";
        
        // Map linker versions to Visual Studio versions
        var linkerVersion = linkerMajor + "." + linkerMinor;
        switch (linkerVersion) {
            case "6.0": sVersion = "6.0 (VC 6.0)"; break;
            case "7.0": sVersion = "2002 (VC 7.0)"; break;
            case "7.1": sVersion = "2003 (VC 7.1)"; break;
            case "8.0": sVersion = "2005 (VC 8.0)"; break;
            case "9.0": sVersion = "2008 (VC 9.0)"; break;
            case "10.0": sVersion = "2010 (VC 10.0)"; break;
            case "11.0": sVersion = "2012 (VC 11.0)"; break;
            case "12.0": sVersion = "2013 (VC 12.0)"; break;
            case "14.0": sVersion = "2015 (VC 14.0)"; break;
            case "14.1": sVersion = "2017 (VC 14.1)"; break;
            case "14.2": sVersion = "2019 (VC 14.2)"; break;
            case "14.3": sVersion = "2022 (VC 14.3)"; break;
        }
        
        bDetected = true;
    }
}
```

#### Delphi Compiler Detection
```javascript
// Delphi/Borland compiler detection
function detectDelphi() {
    if (PE.isNET()) {
        // .NET Delphi detection
        if (PE.isNetTypePresent("Borland.Vcl", "Types")) {
            sName = "Borland Delphi";
            sVersion = "8";
            sOptions = ".NET";
            bDetected = true;
        } else if (PE.isNetTypePresent("Borland.Delphi", "System")) {
            sName = "Borland Delphi";
            sVersion = "8 WinForm";
            sOptions = ".NET";
            bDetected = true;
        }
    } else {
        // Native Delphi detection through section analysis
        var nSectionOffset = PE.getSectionFileOffset(0);
        var nSectionSize = PE.getSectionFileSize(0);
        
        // Look for Delphi runtime signatures
        var delphiSignature = PE.findSignature(nSectionOffset, nSectionSize, "53574156");
        if (delphiSignature != -1) {
            sName = "Borland Delphi";
            
            // Version detection based on specific patterns
            if (PE.findSignature(nSectionOffset, nSectionSize, "4465706869") != -1) {
                // More specific version detection logic here
                sVersion = "7.0+";
            }
            
            bDetected = true;
        }
    }
}
```

### .NET Obfuscator Detection

#### ConfuserEx Detection
```javascript
// ConfuserEx obfuscator detection
function detectConfuserEx() {
    if (!PE.isNET()) return;
    
    // Check for ConfusedByAttribute
    if (PE.isNetTypePresent("", "ConfusedByAttribute")) {
        sName = "Confuser";
        
        // Try to extract version from string
        var nVersionOffset = PE.findString(
            PE.getSectionFileOffset(0), 
            PE.getSectionFileSize(0), 
            "Confuser v"
        );
        
        if (nVersionOffset != -1) {
            sVersion = PE.getString(nVersionOffset + 10);
        } else {
            sVersion = "1.X";
        }
        
        bDetected = true;
    } else if (PE.getNumberOfSections() >= 2) {
        // Check for ConfuserEx signature
        var nVersionOffset = PE.findString(
            PE.getSectionFileOffset(1), 
            PE.getSectionFileSize(1), 
            "ConfuserEx v"
        );
        
        if (nVersionOffset != -1) {
            sName = "ConfuserEx";
            sVersion = PE.getString(nVersionOffset + 12, 7);
            bDetected = true;
        }
    }
}
```

### Installer Detection

#### InstallShield Detection
```javascript
// InstallShield installer detection
function detectInstallShield() {
    // Check entry point signature
    if (PE.compareEP("64a1........558bec6a..68........68........50648925........83ec..5356578965..ff15")) {
        sName = "InstallShield";
        
        if (PE.isOverlayPresent()) {
            var overlayOffset = PE.getOverlayOffset();
            var nOffset = PE.readByte(overlayOffset) + overlayOffset + 12;
            
            if (PE.compare("135d658c", nOffset)) {
                sVersion = "3.X";
                bDetected = true;
            } else if (PE.compare("'PK'0304", nOffset)) {
                sVersion = "3.X";
                sOptions = "ZIP compressed";
                bDetected = true;
            }
        } else {
            // Check for IS2 resource type
            var numResources = PE.getNumberOfResources();
            for (var i = 0; i < numResources; i++) {
                var resourceType = PE.getResourceTypeByNumber(i);
                if (resourceType == 3000) { // IS2 type
                    var resourceOffset = PE.getResourceOffsetByNumber(i);
                    if (PE.compare("'SZDD'", resourceOffset)) {
                        sVersion = "2.X";
                        bDetected = true;
                        break;
                    }
                }
            }
        }
        
        // Check for cabinet section
        if (PE.isSectionNamePresent("_cabinet")) {
            bDetected = true;
        }
    }
}
```

### Advanced Analysis Examples

#### Import Hash Calculation for Malware Analysis
```javascript
// Calculate import hashes for malware family clustering
function analyzeImportHash() {
    if (!PE.isImportPresent()) return;
    
    var importHash32 = PE.getImportHash32();
    var importHash64 = PE.getImportHash64();
    
    // Known malware family hashes
    var knownHashes = {
        0x1234ABCD: "Emotet variant",
        0x5678EFAB: "TrickBot loader", 
        0x9ABC1234: "Cobalt Strike beacon"
    };
    
    if (knownHashes[importHash32]) {
        sMalwareFamily = knownHashes[importHash32];
        sOptions = "ImpHash: " + importHash32.toString(16);
    }
    
    // Check for suspicious import patterns
    var suspiciousLibs = ["ntdll.dll", "kernel32.dll"];
    var suspiciousFunctions = ["NtCreateFile", "VirtualProtect", "LoadLibraryA"];
    
    var suspiciousCount = 0;
    for (var i = 0; i < suspiciousLibs.length; i++) {
        if (PE.isLibraryPresent(suspiciousLibs[i])) {
            for (var j = 0; j < suspiciousFunctions.length; j++) {
                if (PE.isLibraryFunctionPresent(suspiciousLibs[i], suspiciousFunctions[j])) {
                    suspiciousCount++;
                }
            }
        }
    }
    
    if (suspiciousCount > 2) {
        sFlags = "Potentially suspicious imports";
    }
}
```

#### Section Analysis for Packing Detection
```javascript
// Comprehensive section analysis for packer detection
function analyzeSections() {
    var numSections = PE.getNumberOfSections();
    var suspiciousNames = [".packed", ".upx0", ".upx1", ".aspack", ".vmp0", ".vmp1"];
    var packerIndicators = [];
    
    for (var i = 0; i < numSections; i++) {
        var sectionName = PE.getSectionName(i);
        var virtualSize = PE.getSectionVirtualSize(i);
        var rawSize = PE.getSectionFileSize(i);
        var characteristics = PE.getSectionCharacteristics(i);
        
        // Check for suspicious section names
        for (var j = 0; j < suspiciousNames.length; j++) {
            if (sectionName.toLowerCase().includes(suspiciousNames[j])) {
                packerIndicators.push("Suspicious section: " + sectionName);
            }
        }
        
        // Check for high entropy sections (potential packed code)
        if (rawSize > 0) {
            var entropy = PE.calculateEntropy(
                PE.getSectionFileOffset(i), 
                rawSize
            );
            
            if (entropy > 7.5) {
                packerIndicators.push("High entropy section: " + sectionName);
            }
        }
        
        // Check for executable sections with size anomalies
        if (characteristics & 0x20000000) { // IMAGE_SCN_MEM_EXECUTE
            if (virtualSize > rawSize * 10) {
                packerIndicators.push("Inflated section: " + sectionName);
            }
        }
    }
    
    if (packerIndicators.length > 0) {
        sOptions = packerIndicators.join(", ");
        sPossiblePacker = "Detected";
    }
}
```

#### .NET Metadata Deep Analysis
```javascript
// Deep .NET metadata analysis
function analyzeNETMetadata() {
    if (!PE.isNET()) return;
    
    var netVersion = PE.getNETVersion();
    var frameworkTypes = [
        {namespace: "System", type: "Console", description: "Console operations"},
        {namespace: "System.IO", type: "File", description: "File operations"},
        {namespace: "System.Net", type: "WebClient", description: "Network operations"},
        {namespace: "System.Reflection", type: "Assembly", description: "Reflection capabilities"},
        {namespace: "System.Security.Cryptography", type: "AES", description: "Cryptography"},
        {namespace: "Microsoft.Win32", type: "Registry", description: "Registry access"}
    ];
    
    var capabilities = [];
    for (var i = 0; i < frameworkTypes.length; i++) {
        var type = frameworkTypes[i];
        if (PE.isNetTypePresent(type.namespace, type.type)) {
            capabilities.push(type.description);
        }
    }
    
    // Check for obfuscation indicators
    var obfuscationIndicators = ["ConfuserEx", "Babel", "Dotfuscator", "SmartAssembly"];
    for (var i = 0; i < obfuscationIndicators.length; i++) {
        if (PE.isNETStringPresent(obfuscationIndicators[i])) {
            sObfuscator = obfuscationIndicators[i];
            break;
        }
    }
    
    // Check for anti-debugging
    if (PE.isNetMethodPresent("System.Diagnostics", "Debugger", "IsAttached")) {
        capabilities.push("Anti-debugging");
    }
    
    sCapabilities = capabilities.join(", ");
    sNETVersion = netVersion;
}
```

## Usage Examples

### Basic PE Analysis
```javascript
// Check if file is a PE
if (PE.isPEPlus()) {
    sArchitecture = "x64";
} else {
    sArchitecture = "x86";
}

// Analyze sections
var textSection = PE.getSectionNumber(".text");
if (textSection != -1) {
    var codeSize = PE.getSectionVirtualSize(textSection);
}

// Check imports
if (PE.isLibraryPresent("ntdll.dll")) {
    if (PE.isLibraryFunctionPresent("ntdll.dll", "NtCreateFile")) {
        bUsesNativeAPI = true;
    }
}
```

### .NET Analysis
```javascript
if (PE.isNET()) {
    var netVersion = PE.getNETVersion();
    
    // Check for obfuscation
    if (PE.isNETStringPresent("ConfuserEx") || 
        PE.isNETStringPresent("Babel")) {
        sObfuscator = "Detected";
    }
    
    // Analyze types
    if (PE.isNetTypePresent("System.Net", "WebClient")) {
        bNetworkCapable = true;
    }
}
```

### Malware Analysis
```javascript
// Calculate import hash for similarity analysis
var importHash32 = PE.getImportHash32();

// Check for suspicious sections
if (PE.isSectionNamePresent(".packed") || 
    PE.isSectionNamePresent("UPX0")) {
    sPacker = "Detected";
}

// Analyze exports for DLL classification
if (PE.isExportPresent()) {
    var numExports = PE.getNumberOfExportFunctions();
    if (numExports > 100) {
        sClassification = "Library";
    }
}
```
