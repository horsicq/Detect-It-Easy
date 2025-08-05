# Signature Patterns Reference

This document describes the signature pattern formats used in Detect-It-Easy for binary file detection.

## Table of Contents
- [Basic Signature Format](#basic-signature-format)
- [Wildcard Characters](#wildcard-characters)
- [Special Signatures](#special-signatures)
- [Text Matching](#text-matching)
- [Advanced Patterns](#advanced-patterns)
- [Examples](#examples)

## Basic Signature Format

Signatures are hexadecimal patterns that match byte sequences in files. They can contain:
- **Hexadecimal bytes** - Exact byte values (e.g., `4D 5A`, `FF D8`)
- **Wildcards** - Variable bytes that can match any value
- **Text strings** - ASCII text enclosed in single quotes
- **Special symbols** - Jump distances, addresses, and conditional matches

### Standard Format Examples
```
4D 5A 90 ?? ?? 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00
4D 5A 90 .. .. 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00
'MZ'90....00000004000000FFFF0000B8000000
```

All three examples above are equivalent and match a DOS/PE executable header.

## Wildcard Characters

| Symbol | Description | Example |
|--------|-------------|---------|
| `??` | Any single byte | `4D 5A ?? ??` |
| `..` | Any single byte (alternative) | `4D 5A .. ..` |
| `....` | Any 2 bytes | `4D 5A....` |
| `........` | Any 4 bytes | `FF D8........` |

**Examples:**
```javascript
// Match JPEG header with any app marker
if (Binary.compare("FFD8FFE?")) {
    sName = "JPEG image";
}

// Match PE header with any checksum
if (Binary.compare("4D5A........E8........")) {
    sName = "PE executable";
}
```

## Special Signatures

### Jump Signatures
Used to match relative jumps and calls in executable code.

| Pattern | Description | Example |
|---------|-------------|---------|
| `$$` | 1-byte relative jump | `EB$$` |
| `$$$$` | 2-byte relative jump | `E8$$$$` |
| `$$$$$$$$` | 4-byte relative jump | `E8$$$$$$$$` |

**Examples:**
```javascript
// Match common shellcode pattern
if (Binary.compare("83CDFFEB$$8B1E83EEFC11DB72$$8A0646")) {
    sName = "Shellcode pattern";
}
```

### Address Signatures
Used to match absolute addresses in code.

| Pattern | Description | Example |
|---------|-------------|---------|
| `####` | 2-byte address | `68####` |
| `########` | 4-byte address | `68########` |

**Examples:**
```javascript
// Match PUSH instruction with any address
if (Binary.compare("68########55")) {
    sName = "Common packer pattern";
}
```

### Conditional Wildcards

| Pattern | Description | Usage |
|---------|-------------|-------|
| `**` | Not null byte | `**CDFFEB` |
| `!!` | Not ANSI character | `!!CDFFEB` |
| `__` | Not ANSI and not null | `__CDFFEB` |

**Examples:**
```javascript
// Match non-null byte followed by specific pattern
if (Binary.compare("**4D5A")) {
    // Ensures first byte is not 0x00
}

// Match non-ASCII followed by pattern
if (Binary.compare("!!FFD8")) {
    // Ensures first byte is not printable ASCII
}
```

## Text Matching

Enclose ASCII text in single quotes to match string literals:

```javascript
// SQLite database detection
if (Binary.compare("'SQLite format 3'00")) {
    sName = "SQLite database";
}

// 7-Zip signature
if (Binary.compare("'7z'BCAF271C")) {
    sName = "7-Zip archive";
}

// Mixed text and hex
if (Binary.compare("FFD8FFE0....'JFIF'00")) {
    sName = "JPEG JFIF";
}
```

## Advanced Patterns

### Delta Signatures
Match byte differences rather than absolute values:

```javascript
// Match increasing byte sequence
if (Binary.compare("CD+EB")) {
    // 0xCD followed by any byte >= 0xEB
}
```

### Complex Combinations
```javascript
// Advanced PE detection
if (Binary.compare("4D5A........'PE'0000")) {
    // DOS header + PE signature
    
    // Check for .NET
    if (Binary.compare("........'.text'", 0x18)) {
        sOptions = ".NET";
    }
}

// ZIP file detection with various markers
if (Binary.compare("'PK'0304") || 
    Binary.compare("'PK'0506") || 
    Binary.compare("'PK'0708")) {
    sName = "ZIP archive";
}
```

## Examples

### Executable Formats
```javascript
// Windows PE
if (Binary.compare("4D5A") && Binary.compare("'PE'0000", Binary.read_uint32(0x3C))) {
    sName = "PE executable";
}

// Linux ELF
if (Binary.compare("7F'ELF'")) {
    sName = "ELF executable";
    
    switch (Binary.readByte(4)) {
        case 1: sOptions = "32-bit"; break;
        case 2: sOptions = "64-bit"; break;
    }
}

// macOS Mach-O
if (Binary.compare("FEEDFACE") || Binary.compare("FEEDFACF")) {
    sName = "Mach-O executable";
}
```

### Archive Formats
```javascript
// RAR archive
if (Binary.compare("'Rar!'1A0700")) {
    sVersion = "1.5-4.x";
} else if (Binary.compare("'Rar!'1A070100")) {
    sVersion = "5.0+";
}

// TAR archive (POSIX format)
if (Binary.compare("'ustar'0030", 257)) {
    sName = "TAR archive";
    sOptions = "POSIX format";
}
```

### Media Formats
```javascript
// PNG image
if (Binary.compare("89'PNG'0D0A1A0A")) {
    sName = "PNG image";
    
    // Get dimensions from IHDR
    var width = Binary.read_uint32(16, true);
    var height = Binary.read_uint32(20, true);
    sOptions = width + "x" + height;
}

// MP3 audio
if (Binary.compare("'ID3'") || Binary.compare("FFF?")) {
    sName = "MP3 audio";
    
    if (Binary.compare("'ID3'")) {
        var version = Binary.readByte(3) + "." + Binary.readByte(4);
        sOptions = "ID3v" + version;
    }
}
```

### Database Files
```javascript
// Microsoft Access
if (Binary.compare("'Standard Jet DB'")) {
    sName = "Microsoft Access database";
}

// MySQL MyISAM
if (Binary.compare("FE000001")) {
    sName = "MySQL MyISAM table";
}
```

This signature system provides powerful pattern matching capabilities for accurate file format detection across a wide range of binary file types.