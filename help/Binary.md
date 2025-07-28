# Binary Class Reference

The Binary class provides low-level file analysis and manipulation capabilities. This class is used when no other specialized class matches the file format.

## Table of Contents
- [File Information](#file-information)
- [Binary Comparison and Search](#binary-comparison-and-search)
- [Data Reading Methods](#data-reading-methods)
- [String Operations](#string-operations)
- [Hash and Checksum Functions](#hash-and-checksum-functions)
- [File Format Detection](#file-format-detection)
- [Utility Functions](#utility-functions)
- [Real-World Detection Examples](#real-world-detection-examples)
- [Method Shortcuts](#method-shortcuts)

## File Information

### getSize()
**`qint64 getSize()`** - Get the size of the file in bytes.

```javascript
var fileSize = Binary.getSize();
```

## Binary Comparison and Search

### compare()
**`bool compare(QString sSignature, qint64 nOffset=0)`** - Compares bytes with a hexadecimal string signature.

The signature may contain both lowercase and uppercase hexadecimal digits.
Spaces are skipped: **AA BB** = **AABB**
Text may be matched using single quotes: **"01'Test'01"**

**Special Symbols:**
* `#` - Absolute jump (e.g., "68########55")
* `$` - Relative jump (e.g., "E8$$$$$$$$55")

**Wildcard Parameters:**

| Parameter | Description                                      |
|-----------|--------------------------------------------------|
| `..`      | Represent any byte                               |
| `??`      | Represent any byte                               |
| `**`      | Not null                                         |
| `%%`      | ANSI character                                   |
| `!%`      | Not ANSI character                               |
| `_%`      | Not ANSI and not null                            |

**Examples:**
```javascript
// Compare file header (nOffset=0)
if (Binary.compare("'7z'BCAF271C")) {
    sVersion = Binary.readByte(6) + "." + Binary.readByte(7);
    bDetected = true;
}

// Compare from specific offset
if (Binary.compare("'WAVEfmt '", 8)) {
    bDetected = true;
}

// JPEG file detection with JFIF header
if (Binary.compare("FFD8FFE0....'JFIF'00")) {
    bDetected = true;
    sVersion = Binary.readByte(11) + "." + Binary.readByte(12);
}

// SQLite database detection
if (Binary.compare("'SQLite format 3'00")) {
    sName = "SQLite 3 database";
    bDetected = true;
}

// RIFF/WAV file detection
if (Binary.compare("'RIFF'........'WAVE'")) {
    sFormat = "WAV Audio File";
    bDetected = true;
}

// Python compiled module detection
if (Binary.compare("?? 0D 0D 0A") && Binary.read_uint16(0x02) == 0x0A0D) {
    var magicValue = Binary.read_uint16(0);
    if (magicValue == 62211) {
        sVersion = "Python 3.6";
        bDetected = true;
    }
}
```

### compareEP()
**`bool compareEP(QString sSignature, qint64 nOffset=0)`** - Compare bytes at the Entry Point.

**Parameters:**
* `sSignature` - The hexadecimal signature to compare
* `nOffset` - Offset from the entry point (default: 0)

**Examples:**
```javascript
if (PE.compareEP("2C81", 8)) {
    sVersion = "1.98";
}

if (PE.compareEP("EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24")) {
    bDetected = true;
}
```

### Search Functions

#### findSignature()
**`qint64 findSignature(qint64 nOffset, qint64 nSize, QString sSignature)`** - Search for a signature in the file.

**Returns:** Offset in the file if found, `-1` otherwise.

#### findString()
**`qint64 findString(qint64 nOffset, qint64 nSize, QString sString)`** - Search for a string in the file.

**Returns:** Offset in the file if found, `-1` otherwise.

#### findByte()
**`qint64 findByte(qint64 nOffset, qint64 nSize, quint8 nValue)`** - Search for a byte value in the file.

**Returns:** Offset in the file if found, `-1` otherwise.

#### findWord()
**`qint64 findWord(qint64 nOffset, qint64 nSize, quint16 nValue)`** - Search for a 16-bit word in the file.

**Returns:** Offset in the file if found, `-1` otherwise.

#### findDword()
**`qint64 findDword(qint64 nOffset, qint64 nSize, quint32 nValue)`** - Search for a 32-bit double word in the file.

**Returns:** Offset in the file if found, `-1` otherwise.

### isSignaturePresent()
**`bool isSignaturePresent(qint64 nOffset, qint64 nSize, QString sSignature)`** - Check if a signature exists in a file region.

Uses the same signature format as [`compare()`](#compare).

## Data Reading Methods

### Basic Integer Types

#### 8-bit Values
**`quint8 readByte(qint64 nOffset)`** - Read an unsigned byte value.

**`qint8 readSByte(qint64 nOffset)`** - Read a signed byte value.

#### 16-bit Values  
**`quint16 readWord(qint64 nOffset)`** - Read an unsigned 16-bit word.

**`qint16 readSWord(qint64 nOffset)`** - Read a signed 16-bit word.

#### 32-bit Values
**`quint32 readDword(qint64 nOffset)`** - Read an unsigned 32-bit double word.

**`qint32 readSDword(qint64 nOffset)`** - Read a signed 32-bit double word.

#### 64-bit Values
**`quint64 readQword(qint64 nOffset)`** - Read an unsigned 64-bit quad word.

**`qint64 readSQword(qint64 nOffset)`** - Read a signed 64-bit quad word.

### Enhanced Reading Methods

#### Integer Types with Endianness Support
**`quint8 read_uint8(qint64 nOffset)`** - Read unsigned 8-bit integer.

**`qint8 read_int8(qint64 nOffset)`** - Read signed 8-bit integer.

**`quint16 read_uint16(qint64 nOffset, bool bIsBigEndian=false)`** - Read unsigned 16-bit integer.

**`qint16 read_int16(qint64 nOffset, bool bIsBigEndian=false)`** - Read signed 16-bit integer.

**`quint32 read_uint24(qint64 nOffset, bool bIsBigEndian=false)`** - Read unsigned 24-bit integer.

**`qint32 read_int24(qint64 nOffset, bool bIsBigEndian=false)`** - Read signed 24-bit integer.

**`quint32 read_uint32(qint64 nOffset, bool bIsBigEndian=false)`** - Read unsigned 32-bit integer.

**`qint32 read_int32(qint64 nOffset, bool bIsBigEndian=false)`** - Read signed 32-bit integer.

**`quint64 read_uint64(qint64 nOffset, bool bIsBigEndian=false)`** - Read unsigned 64-bit integer.

**`qint64 read_int64(qint64 nOffset, bool bIsBigEndian=false)`** - Read signed 64-bit integer.

#### Floating Point Types
**`float read_float(qint64 nOffset, bool bIsBigEndian=false)`** - Read 32-bit float.

**`double read_double(qint64 nOffset, bool bIsBigEndian=false)`** - Read 64-bit double.

**`float read_float16(qint64 nOffset, bool bIsBigEndian=false)`** - Read 16-bit half precision float.

**`float read_float32(qint64 nOffset, bool bIsBigEndian=false)`** - Read 32-bit single precision float.

**`double read_float64(qint64 nOffset, bool bIsBigEndian=false)`** - Read 64-bit double precision float.

#### Binary Coded Decimal (BCD)
**`quint8 read_bcd_uint8(qint64 nOffset)`** - Read 8-bit BCD value.

**`quint16 read_bcd_uint16(qint64 nOffset, bool bIsBigEndian=false)`** - Read 16-bit BCD value.

**`quint32 read_bcd_uint32(qint64 nOffset, bool bIsBigEndian=false)`** - Read 32-bit BCD value.

**`quint64 read_bcd_uint64(qint64 nOffset, bool bIsBigEndian=false)`** - Read 64-bit BCD value.

#### Special Data Types
**`QString read_UUID_bytes(qint64 nOffset)`** - Read UUID as raw bytes.

**`QString read_UUID(qint64 nOffset, bool bIsBigEndian=false)`** - Read formatted UUID.

**`QList<QVariant> readBytes(qint64 nOffset, qint64 nSize, bool bReplaceZeroWithSpace=false)`** - Read raw bytes as array.

## String Operations

### Basic String Reading
**`QString getString(qint64 nOffset, qint64 nMaxSize=50)`** - Read a null-terminated string.

**Parameters:**
* `nOffset` - File offset to read from
* `nMaxSize` - Maximum string length in bytes (default: 50)

**Example:**
```javascript
var sString = Binary.getString(0x100, 32);  // Read max 32 bytes from offset 0x100
var sString = Binary.getString(60);         // Read max 50 bytes from offset 60

// Detect UTF-8 BOM in text files
var sText = Binary.getString(0, Math.min(Binary.getSize(), 3));
if (/^\xef\xbb\xbf/.test(sText)) {
    sName = "UTF-8 text with BOM";
}

// Check line ending types
var size = Binary.getSize() < 4096 ? Binary.getSize() : 4096;
var pos = Binary.findByte(0, size, 10); // Look for LF (0x0A)
if (pos !== -1) {
    // Check if CRLF or just LF
    var hasCR = (pos != 0 && Binary.readByte(pos - 1) == 13) || 
                (pos + 1 < Binary.getSize() && Binary.readByte(pos + 1) == 13);
    sLineEnding = hasCR ? "CRLF" : "LF";
} else if (Binary.findByte(0, size, 13) != -1) {
    sLineEnding = "CR"; // Mac classic
}
```

### Encoding-Specific String Reading
**`QString read_ansiString(qint64 nOffset, qint64 nMaxSize=50)`** - Read ANSI encoded string.

**`QString read_unicodeString(qint64 nOffset, qint64 nMaxSize=50)`** - Read Unicode (UTF-16) string.

**`QString read_utf8String(qint64 nOffset, qint64 nMaxSize=50)`** - Read UTF-8 encoded string.

**`QString read_ucsdString(qint64 nOffset)`** - Read UCSD Pascal-style string (length-prefixed).

### Advanced String Reading
**`QString read_codePageString(qint64 nOffset, qint64 nMaxByteSize=256, QString sCodePage="System")`** - Read string with specific code page encoding.

**Supported Code Pages:**
```
System, ISO-8859-1, ISO-8859-2, ISO-8859-3, ISO-8859-4, ISO-8859-5,
ISO-8859-7, ISO-8859-9, ISO-8859-10, ISO-8859-13, ISO-8859-14,
ISO-8859-15, ISO-8859-16, ISO-8859-6, ISO-8859-8, Shift_JIS, EUC-JP,
EUC-KR, ISO-2022-JP, UTF-8, UTF-16BE, UTF-16LE, UTF-16, UTF-32,
UTF-32BE, UTF-32LE, GBK, GB18030, GB2312, Big5, Big5-HKSCS,
windows-1250 through windows-1258, KOI8-R, KOI8-U, IBM850, IBM866,
IBM874, TIS-620, macintosh, hp-roman8, TSCII, WINSAMI2, windows-949,
iscii-dev, iscii-bng, iscii-pnj, iscii-gjr, iscii-ori, iscii-tml,
iscii-tlg, iscii-knd, iscii-mlm
```

### String Search Functions
**`qint64 find_ansiString(qint64 nOffset, qint64 nSize, QString sString)`** - Search for ANSI string.

**`qint64 find_unicodeString(qint64 nOffset, qint64 nSize, QString sString)`** - Search for Unicode string.

**`qint64 find_utf8String(qint64 nOffset, qint64 nSize, QString sString)`** - Search for UTF-8 string.

### String Utility Functions
**`QString upperCase(QString sString)`** - Convert string to uppercase.

**`QString lowerCase(QString sString)`** - Convert string to lowercase.

**`QString cleanString(QString sString)`** - Clean and normalize string content.

## Hash and Checksum Functions

### CRC Functions
**`QString calculateCRC32(qint64 nOffset, qint64 nSize)`** - Calculate CRC32 hash as hex string.

**`quint16 crc16(qint64 nOffset, qint64 nSize, quint16 nInit=0)`** - Calculate CRC16 checksum.

**`quint32 crc32(qint64 nOffset, qint64 nSize, quint32 nInit=0)`** - Calculate CRC32 checksum.

### Cryptographic Hashes
**`QString calculateMD5(qint64 nOffset, qint64 nSize)`** - Calculate MD5 hash of file region.

### Other Checksums
**`quint32 adler32(qint64 nOffset, qint64 nSize)`** - Calculate Adler-32 checksum.

**`double calculateEntropy(qint64 nOffset, qint64 nSize)`** - Calculate entropy (bits per byte, max 8.0).

## File Format Detection

### Text Format Detection
**`bool isPlainText()`** - Check if file contains plain text.

**`bool isUTF8Text()`** - Check if file contains UTF-8 encoded text.

**`bool isUnicodeText()`** - Check if file contains Unicode text.

**`bool isText()`** - Check if file contains any text format.

**Example:**
```javascript
if (Binary.isPlainText()) {
    sName = "Plain text file";
    
    // Check for specific encodings
    if (Binary.isUTF8Text()) {
        sOptions = "UTF-8";
    } else if (Binary.isUnicodeText()) {
        sOptions = "Unicode";
    }
    
    bDetected = true;
}
```

### JPEG Detection and Analysis
**`bool isJpeg()`** - Check if file is JPEG format.

**`QString getJpegComment()`** - Extract JPEG comment field.

**`QString getJpegDqtMD5()`** - Get MD5 hash of JPEG quantization tables.

**`bool isJpegChunkPresent(qint32 nID)`** - Check for specific JPEG chunk.

**`bool isJpegExifPresent()`** - Check if JPEG contains EXIF data.

**`QString getJpegExifCameraName()`** - Extract camera name from EXIF data.

**Example:**
```javascript
if (Binary.isJpeg()) {
    sName = "JPEG image";
    
    // Extract comment if present
    var comment = Binary.getJpegComment();
    if (comment.length > 0) {
        sOptions = "comment: " + comment;
    }
    
    // Check for EXIF data
    if (Binary.isJpegExifPresent()) {
        var cameraName = Binary.getJpegExifCameraName();
        if (cameraName.length > 0) {
            sOptions += ", camera: " + cameraName;
        }
    }
    
    // Get quantization table hash for identification
    var dqtHash = Binary.getJpegDqtMD5();
    if (dqtHash.length > 0) {
        sOptions += ", DQT hash: " + dqtHash.substring(0, 8);
    }
    
    bDetected = true;
}
```

### Compression Detection
**`qint64 detectZLIB(qint64 nOffset, qint64 nSize)`** - Detect ZLIB compressed data.

**`qint64 detectGZIP(qint64 nOffset, qint64 nSize)`** - Detect GZIP compressed data.

**`qint64 detectZIP(qint64 nOffset, qint64 nSize)`** - Detect ZIP compressed data.

### Compression Support
**`QList<QString> getListOfCompressionMethods()`** - Get available compression methods.

**`QList<QVariant> decompressBytes(qint64 nOffset, qint64 nSize, QString sCompressionMethod)`** - Decompress data.

**`qint64 getCompressedDataSize(qint64 nOffset, qint64 nSize, QString sCompressionMethod)`** - Get compressed data size.

## Utility Functions

### File Path Operations
**`QString getFileDirectory()`** - Get directory containing the file.

**`QString getFileBaseName()`** - Get base filename without path or extension.

**`QString getFileCompleteSuffix()`** - Get complete file extension.

**`QString getFileSuffix()`** - Get primary file extension.

### Memory and Address Operations
**`qint64 RVAToOffset(qint64 nRVA)`** - Convert Relative Virtual Address to file offset.

**`qint64 VAToOffset(qint64 nVA)`** - Convert Virtual Address to file offset.

**`qint64 OffsetToVA(qint64 nOffset)`** - Convert file offset to Virtual Address.

**`qint64 OffsetToRVA(qint64 nOffset)`** - Convert file offset to Relative Virtual Address.

**`qint64 getImageBase()`** - Get image base address.

### Entry Point and Overlay Operations
**`qint64 getEntryPointOffset()`** - Get entry point file offset.

**`qint64 getAddressOfEntryPoint()`** - Get entry point virtual address.

**`qint64 getOverlayOffset()`** - Get overlay data offset.

**`qint64 getOverlaySize()`** - Get overlay data size.

**`bool isOverlayPresent()`** - Check if file has overlay data.

**`bool compareOverlay(QString sSignature, qint64 nOffset=0)`** - Compare overlay data signature.

### Data Conversion
**`quint32 swapBytes(quint32 nValue)`** - Swap byte order of 32-bit value.

Example: `0x11223344` becomes `0x44332211`

**`QString bytesCountToString(quint64 nValue, quint32 nBase=1024)`** - Convert byte count to human readable string.

**`QString getSignature(qint64 nOffset, qint64 nSize)`** - Get hex signature from file region.

**Example:**
```javascript
if (Binary.getSignature(0, 4) == "AA5411DD") {
    bDetected = true;
}

// SQLite version detection from header
var nSQLiteVersionNumber = Binary.read_uint32(0x60, true); // Big-endian
var nMajor = Math.floor(nSQLiteVersionNumber / 1000000);
var nMinor = Math.floor((nSQLiteVersionNumber - nMajor * 1000000) / 1000);
var nRelease = nSQLiteVersionNumber - (nMajor * 1000000) - (nMinor * 1000);
sVersion = nMajor + "." + nMinor + "." + nRelease;

// Extract JPEG dimensions and version
if (Binary.compare("FFD8FFE0....'JFIF'00")) {
    sVersion = Binary.readByte(11) + "." + Binary.readByte(12);
    
    // Search for Start Of Frame to get dimensions
    var nOffset = 2;
    while (nOffset < Binary.getSize()) {
        var wTag = Binary.read_uint16(nOffset, true); // Big-endian
        if (wTag >= 0xFFC0 && wTag <= 0xFFC3) {
            var width = Binary.read_uint16(nOffset + 7, true);
            var height = Binary.read_uint16(nOffset + 5, true);
            sOptions = width + "x" + height;
            break;
        }
        nOffset += 2;
    }
}
```

### Architecture and Build Detection
**`bool is16()`** - Check if file is 16-bit architecture.

**`bool is32()`** - Check if file is 32-bit architecture.

**`bool is64()`** - Check if file is 64-bit architecture.

**`bool isReleaseBuild()`** - Check if file is a release build.

**`bool isDebugBuild()`** - Check if file is a debug build.

### File Properties and Validation
**`bool isSigned()`** - Check if file is digitally signed.

**`bool isOverlay()`** - Check if current context is overlay data.

**`bool isResource()`** - Check if current context is resource data.

**`bool isDebugData()`** - Check if current context is debug data.

**`bool isFilePart()`** - Check if current context is part of a file.

### Validation Functions
**`bool isChecksumCorrect()`** - Verify file checksum.

**`bool isEntryPointCorrect()`** - Verify entry point validity.

**`bool isSectionAlignmentCorrect()`** - Verify section alignment.

**`bool isFileAlignmentCorrect()`** - Verify file alignment.

**`bool isHeaderCorrect()`** - Verify file header.

**`bool isRelocsTableCorrect()`** - Verify relocations table.

**`bool isImportTableCorrect()`** - Verify import table.

**`bool isExportTableCorrect()`** - Verify export table.

**`bool isResourcesTableCorrect()`** - Verify resources table.

**`bool isSectionsTableCorrect()`** - Verify sections table.

### Scan Mode Detection
**`bool isDeepScan()`** - Check if deep scan mode is enabled.

**`bool isHeuristicScan()`** - Check if heuristic scan mode is enabled.

**`bool isAggressiveScan()`** - Check if aggressive scan mode is enabled.

**`bool isVerbose()`** - Check if verbose mode is enabled.

### Performance and Debugging
**`bool isProfiling()`** - Check if profiling mode is enabled.

**`qint64 startTiming()`** - Start performance timing.

**`qint64 endTiming(qint64 nHandle, const QString &sInfo)`** - End performance timing.

**Example:**
```javascript
// Profiling flag should be set
var nProfiling = Binary.startTiming();
// ... slow code execution ...
var nTime = Binary.endTiming(nProfiling, "PROFILING");
```

### Disassembly Functions
**`qint32 getDisasmLength(qint64 nAddress)`** - Get length of instruction at address.

**`QString getDisasmString(qint64 nAddress)`** - Get disassembly string for instruction.

**`qint64 getDisasmNextAddress(qint64 nAddress)`** - Get address of next instruction.

### System Information
**`QString getOperationSystemName()`** - Get operating system name.

**`QString getOperationSystemVersion()`** - Get operating system version.

**`QString getOperationSystemOptions()`** - Get operating system options.

**`QString getFileFormatName()`** - Get file format name.

**`QString getFileFormatVersion()`** - Get file format version.

**`QString getFileFormatOptions()`** - Get file format options.

### Message and Header Information
**`QList<QString> getFormatMessages()`** - Get format-specific messages.

**`QString getHeaderString()`** - Get header information as string.

### Section-based Operations
**`bool isSignatureInSectionPresent(quint32 nNumber, QString sSignature)`** - Check signature in specific section.

## Real-World Detection Examples

This section contains practical examples from the DIE signature database showing how to use Binary class methods for file format detection.

### Archive Formats

#### ZIP Archive Detection
```javascript
// Basic ZIP detection
if (Binary.compare("'PK'0304") || Binary.compare("'PK'0506") || Binary.compare("'PK'0708")) {
    sName = "ZIP archive";
    bDetected = true;
}

// Enhanced ZIP detection with central directory
if (Binary.compare("'PK'0102")) {
    sName = "ZIP archive (central directory)";
    bDetected = true;
}
```

#### 7-Zip Archive Detection
```javascript
if (Binary.compare("'7z'BCAF271C")) {
    sName = "7-Zip archive";
    sVersion = Binary.readByte(6) + "." + Binary.readByte(7);
    bDetected = true;
}
```

#### RAR Archive Detection
```javascript
if (Binary.compare("'Rar!'1A0700")) {
    sName = "RAR archive";
    sVersion = "1.5-4.x";
    bDetected = true;
} else if (Binary.compare("'Rar!'1A070100")) {
    sName = "RAR archive";
    sVersion = "5.0+";
    bDetected = true;
}
```

### Image Formats

#### JPEG Image Detection
```javascript
if (Binary.compare("FFD8FFE0....'JFIF'00")) {
    sName = "JPEG image";
    bDetected = true;
    
    // Extract version
    sVersion = Binary.readByte(11) + ".";
    if (Binary.readByte(12) < 10) {
        sVersion += "0";
    }
    sVersion += Binary.readByte(12);
    
    // Find dimensions in Start of Frame marker
    var nOffset = 2;
    while (nOffset < Binary.getSize()) {
        var wTag = Binary.read_uint16(nOffset, true);
        if (wTag >= 0xFFC0 && wTag <= 0xFFC3) {
            var width = Binary.read_uint16(nOffset + 7, true);
            var height = Binary.read_uint16(nOffset + 5, true);
            sOptions = width + "x" + height;
            
            // Detect color space
            switch (Binary.readByte(nOffset + 9)) {
                case 1: sOptions += ", greyscale"; break;
                case 3: sOptions += ", YCbCr"; break;
                case 4: sOptions += ", CMYK"; break;
            }
            break;
        }
        var nLength = Binary.read_uint16(nOffset + 2, true);
        nOffset += nLength + 2;
    }
}
```

#### PNG Image Detection
```javascript
if (Binary.compare("89'PNG'0D0A1A0A")) {
    sName = "PNG image";
    bDetected = true;
    
    // Extract dimensions from IHDR chunk
    if (Binary.compare("'IHDR'", 12)) {
        var width = Binary.read_uint32(16, true);
        var height = Binary.read_uint32(20, true);
        var bitDepth = Binary.readByte(24);
        var colorType = Binary.readByte(25);
        
        sOptions = width + "x" + height + ", " + bitDepth + " bit";
        
        switch (colorType) {
            case 0: sOptions += ", grayscale"; break;
            case 2: sOptions += ", RGB"; break;
            case 3: sOptions += ", palette"; break;
            case 4: sOptions += ", grayscale+alpha"; break;
            case 6: sOptions += ", RGBA"; break;
        }
    }
}
```

### Audio Formats

#### WAV Audio Detection
```javascript
if (Binary.compare("'RIFF'........'WAVE'")) {
    sName = "WAV Audio File";
    bDetected = true;
    
    // Parse chunks to extract format information
    var nOffset = 12;
    while (nOffset < Binary.getSize() - 8) {
        var chunkId = Binary.getString(nOffset, 4);
        var chunkSize = Binary.read_uint32(nOffset + 4, false); // Little-endian
        
        if (chunkId == "fmt ") {
            var audioFormat = Binary.read_uint16(nOffset + 8, false);
            var numChannels = Binary.read_uint16(nOffset + 10, false);
            var sampleRate = Binary.read_uint32(nOffset + 12, false);
            var bitsPerSample = Binary.read_uint16(nOffset + 22, false);
            
            sOptions = sampleRate + " Hz, " + numChannels + " channel";
            if (numChannels > 1) sOptions += "s";
            sOptions += ", " + bitsPerSample + " bit";
            
            switch (audioFormat) {
                case 1: sOptions += ", PCM"; break;
                case 3: sOptions += ", IEEE float"; break;
                case 6: sOptions += ", A-law"; break;
                case 7: sOptions += ", μ-law"; break;
            }
            break;
        }
        
        nOffset += 8 + chunkSize;
        if (chunkSize % 2) nOffset++; // Pad to even boundary
    }
}
```

### Database Formats

#### SQLite Database Detection
```javascript
if (Binary.compare("'SQLite format 3'00")) {
    sName = "SQLite 3 database";
    bDetected = true;
    
    // Extract version information
    var nSQLiteVersionNumber = Binary.read_uint32(0x60, true);
    var nMajor = Math.floor(nSQLiteVersionNumber / 1000000);
    var nMinor = Math.floor((nSQLiteVersionNumber - nMajor * 1000000) / 1000);
    var nRelease = nSQLiteVersionNumber - (nMajor * 1000000) - (nMinor * 1000);
    sVersion = nMajor + "." + nMinor + "." + nRelease;
    
    // Check text encoding
    switch (Binary.read_uint32(0x38, true)) {
        case 1: sOptions = "UTF-8"; break;
        case 2: sOptions = "UTF-16LE"; break;
        case 3: sOptions = "UTF-16BE"; break;
    }
    
    // Application ID (if present)
    var nAppID = Binary.read_uint32(0x44, true);
    if (nAppID && Binary.isVerbose()) {
        sOptions += ", AppID:" + nAppID.toString(16);
    }
}
```

### Programming Languages

#### Python Compiled Module Detection
```javascript
if (Binary.compare("?? 0D 0D 0A") && Binary.read_uint16(0x02) == 0x0A0D) {
    sName = "Python compiled module";
    bDetected = true;
    
    var magicValue = Binary.read_uint16(0);
    switch (magicValue) {
        case 20121: sVersion = "1.5-1.5.2"; break;
        case 50428: sVersion = "1.6"; break;
        case 50823: sVersion = "2.0-2.0.1"; break;
        case 60202: sVersion = "2.1-2.1.2"; break;
        case 62211: sVersion = "3.6"; break;
        case 62061: sVersion = "2.4b1"; break;
        case 3394: sVersion = "3.8"; break;
        case 3413: sVersion = "3.9"; break;
        case 3439: sVersion = "3.10"; break;
        case 3495: sVersion = "3.11"; break;
        case 3531: sVersion = "3.12"; break;
        // Add more versions as needed
    }
    
    // Extract timestamp (compilation time)
    var timestamp = Binary.read_uint32(4, false);
    if (timestamp > 0) {
        var date = new Date(timestamp * 1000);
        sOptions = "compiled " + date.toISOString().split('T')[0];
    }
}
```

### Text Format Detection

#### Plain Text with Encoding Detection
```javascript
if (Binary.isPlainText()) {
    sName = "Plain text";
    bDetected = true;
    
    var sText = Binary.getString(0, Math.min(Binary.getSize(), 3));
    
    // Check for UTF-8 BOM
    if (Binary.compare("EFBBBF")) {
        sName = "UTF-8 text";
        sOptions = "BOM";
    }
    // Check for UTF-16 BOM
    else if (Binary.compare("FFFE")) {
        sName = "UTF-16LE text";
        sOptions = "BOM";
    }
    else if (Binary.compare("FEFF")) {
        sName = "UTF-16BE text";
        sOptions = "BOM";
    }
    
    // Detect line endings
    var size = Math.min(Binary.getSize(), 4096);
    var lfPos = Binary.findByte(0, size, 10);  // LF
    var crPos = Binary.findByte(0, size, 13);  // CR
    
    if (lfPos !== -1 && crPos !== -1) {
        sOptions = sOptions ? sOptions + ", CRLF" : "CRLF";
    } else if (lfPos !== -1) {
        sOptions = sOptions ? sOptions + ", LF" : "LF";
    } else if (crPos !== -1) {
        sOptions = sOptions ? sOptions + ", CR" : "CR";
    }
}
```

### Compression Detection

#### ZLIB Data Detection
```javascript
// ZLIB header detection
var firstByte = Binary.readByte(0);
var secondByte = Binary.readByte(1);

if ((firstByte & 0x0F) == 8 && (firstByte >> 4) <= 7) {
    if (((firstByte << 8) | secondByte) % 31 == 0) {
        sName = "ZLIB compressed data";
        bDetected = true;
        
        var compressionLevel = (secondByte >> 6) & 3;
        var windowSize = 1 << ((firstByte >> 4) + 8);
        
        sOptions = "level " + compressionLevel + ", " + windowSize + " byte window";
        
        if (secondByte & 0x20) {
            sOptions += ", dictionary";
        }
    }
}
```

### Executable Format Detection

#### Shellcode Detection
```javascript
// Detect common shellcode patterns
var shellcodePatterns = [
    "EB??5?5?", // JMP short, PUSH/POP pattern
    "E8????????", // CALL instruction
    "83C4??", // ADD ESP, immediate
    "FF??", // Various FF opcodes
];

var bShellcodeDetected = false;
var patternCount = 0;

for (var i = 0; i < shellcodePatterns.length; i++) {
    if (Binary.isSignaturePresent(0, Math.min(256, Binary.getSize()), shellcodePatterns[i])) {
        patternCount++;
    }
}

if (patternCount >= 2) {
    sName = "Possible shellcode";
    sOptions = "pattern count: " + patternCount;
    bDetected = true;
}
```

## Method Shortcuts

For convenience, shorter method names are available:

### Data Type Shortcuts
- `X.U8(a)` = `File.read_uint8(a)`
- `X.I8(a)` = `File.read_int8(a)`
- `X.U16(a, b)` = `File.read_uint16(a, b)`
- `X.I16(a, b)` = `File.read_int16(a, b)`
- `X.F16(a, b)` = `File.read_float16(a, b)`
- `X.U24(a, b)` = `File.read_uint24(a, b)`
- `X.I24(a, b)` = `File.read_int24(a, b)`
- `X.U32(a, b)` = `File.read_uint32(a, b)`
- `X.I32(a, b)` = `File.read_int32(a, b)`
- `X.F32(a, b)` = `File.read_float32(a, b)`
- `X.U64(a, b)` = `File.read_uint64(a, b)`
- `X.I64(a, b)` = `File.read_int64(a, b)`
- `X.F64(a, b)` = `File.read_float64(a, b)`

### String Shortcuts
- `X.SA(a, b)` = `File.read_ansiString(a, b)`
- `X.SC(a, b, c)` = `File.read_codePageString(a, b, c)`
- `X.UСSD(a, b)` = `File.read_ucsdString(a, b)`
- `X.SU8(a, b, c)` = `File.read_utf8String(a, b, c)`
- `X.SU16(a, b, c)` = `File.read_unicodeString(a, b, c)`

### Utility Shortcuts
- `X.Sz()` = `File.getSize()`
- `X.fSig(a, b, c)` = `File.findSignature(a, b, c)`
- `X.fStr(a, b, c)` = `File.findString(a, b, c)`
- `X.c(a, b)` = `File.compare(a, b)`
- `X.BA(a, b, c)` = `File.readBytes(a, b, c)`
