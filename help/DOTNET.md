# DOTNET (.NET / CLI Assembly) Class Reference

The DOTNET class provides analysis of .NET / CLI (Common Language Infrastructure) assemblies. It is backed by the `XCLIAssembly` format and exposes the CLI metadata (streams, tables, strings and blobs) to signatures through the `DOTNET` prefix.

The DOTNET signatures live in the `db/PE/dotnet` database folder and are matched against files detected as CLI assemblies (`FT_CLI_ASSEMBLY`).

## Inheritance

-   **Inherits from Binary class** - All Binary class functions are available with the DOTNET prefix (e.g., `Binary.compareEP` → `DOTNET.compareEP`).

## Table of Contents

-   [Assembly Information](#assembly-information)
-   [.NET String Detection](#net-string-detection)
-   [.NET Blob Analysis](#net-blob-analysis)
-   [.NET Metadata Analysis](#net-metadata-analysis)
-   [Examples](#examples)

## Assembly Information

**`QString getNetVersion()`** - Get the CLI metadata version string (e.g. `v4.0.30319`).

**`QString getNetModuleName()`** - Get the .NET module name from the metadata `Module` table.

**`QString getNetAssemblyName()`** - Get the .NET assembly name from the metadata `Assembly` table.

## .NET String Detection

**`bool isNetStringPresent(QString sString)`** - Check if an ANSI string is present in the `#Strings`/`#US` stream.

**`bool isNetObjectPresent(QString sString)`** - Check if a .NET object (ANSI string) is present.

**`bool isNetUStringPresent(QString sString)`** - Check if a .NET unicode string is present.

**`bool isNetUnicodeStringPresent(QString sString)`** - Check if a .NET unicode string is present.

## .NET Blob Analysis

**`qint64 findSignatureInBlob_NET(QString sSignature)`** - Find a signature in the `#Blob` stream; returns the offset or -1.

**`bool isSignatureInBlobPresent_NET(QString sSignature)`** - Check if a signature exists in the `#Blob` stream.

**`bool compareEP_NET(QString sSignature, qint64 nOffset=0)`** - Compare a signature at the .NET entry point (optionally at `nOffset`).

## .NET Metadata Analysis

**`bool isNetGlobalCctorPresent()`** - Check if a .NET global constructor (`<Module>::.cctor`) is present.

**`bool isNetTypePresent(QString sTypeNamespace, QString sTypeName)`** - Check if a .NET type exists.

**`bool isNetMethodPresent(QString sTypeNamespace, QString sTypeName, QString sMethodName)`** - Check if a .NET method exists.

**`bool isNetFieldPresent(QString sTypeNamespace, QString sTypeName, QString sFieldName)`** - Check if a .NET field exists.

## Examples

```javascript
// meta() runs first; the DOTNET class is available when the file is a CLI assembly.
meta("protector", "");

function detect() {
    if (DOTNET.isNetGlobalCctorPresent()) {
        // Obfuscator / protector detection by embedded strings
        var obfuscators = ["ConfuserEx", "Confuser", "Babel", "Dotfuscator", "SmartAssembly"];
        for (var i = 0; i < obfuscators.length; i++) {
            if (DOTNET.isNetStringPresent(obfuscators[i])) {
                sName = obfuscators[i];
                sVersion = DOTNET.getNetVersion();
                bDetected = true;
                break;
            }
        }
    }

    // Framework capability detection
    if (DOTNET.isNetTypePresent("System.Security.Cryptography", "AES")) {
        // uses AES
    }

    if (DOTNET.isNetMethodPresent("System.Diagnostics", "Debugger", "IsAttached")) {
        // anti-debug
    }

    return result();
}
```
