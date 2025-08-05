# Global Functions Reference

This document describes global functions available across all script classes in Detect-It-Easy.

## Table of Contents
- [Script Management](#script-management)
- [Logging and Debugging](#logging-and-debugging)
- [Result Management](#result-management)
- [Scan Control](#scan-control)
- [Environment Information](#environment-information)

## Script Management

### includeScript()
**`includeScript(sScriptName)`** - Include another script into the current one.

**Parameters:**
* `sScriptName` - The script name. Default path is `$APP/db`

**Examples:**
```javascript
includeScript("Cab");        // Include script $APP/db/Cab
includeScript("PE");         // Include PE format script
includeScript("Archive");    // Include archive detection script
```

## Logging and Debugging

### _log()
**`_log(sString)`** - Display a message in the log window or console for debugging signatures.

**Parameters:**
* `sString` - The message to display (string or number)

**Examples:**
```javascript
_log("Hello world!");        // Display a string
_log(123);                   // Display a number
_log("File size: " + Binary.getSize()); // Display dynamic information
```

### _encodingList()
**`_encodingList()`** - Display all available text codecs in the log.

**Usage:**
```javascript
_encodingList(); // Shows all supported text encodings
```

## Result Management

### result()
**`result()`** - Get the result string appropriate to the current class context.

**Returns:** Formatted result string for the current detection context.

### _setResult()
**`_setResult(sType, sName, sVersion, sOptions)`** - Set detection result.

**Parameters:**
* `sType` - Result type (e.g., "Packer", "Compiler", "Library")
* `sName` - Name of the detected item
* `sVersion` - Version information
* `sOptions` - Additional options or details

**Examples:**
```javascript
_setResult("Packer", "UPX", "3.95", "");
_setResult("Compiler", "Microsoft Visual C++", "2019", "MSVC 16.0");
_setResult("Library", "Qt", "5.15.2", "GUI framework");
```

### _isResultPresent()
**`bool _isResultPresent(sType, sName)`** - Check if a specific result already exists.

**Parameters:**
* `sType` - Result type to check
* `sName` - Result name to check

**Returns:** `true` if the result exists, `false` otherwise

**Examples:**
```javascript
if (!_isResultPresent("Packer", "UPX")) {
    _setResult("Packer", "UPX", version, "");
}
```

### _getNumberOfResults()
**`qint32 _getNumberOfResults(sType)`** - Get the count of results for a specific type.

**Parameters:**
* `sType` - Result type to count

**Returns:** Number of results of the specified type

### _removeResult()
**`void _removeResult(sType, sName)`** - Remove a specific result.

**Parameters:**
* `sType` - Result type to remove
* `sName` - Result name to remove

## Scan Control

### _isStop
**`bool _isStop`** - Check if the scan has been stopped by the user.

**Usage:**
```javascript
if (_isStop) {
    return; // Exit early if scan was cancelled
}
```

### _breakScan()
**`void _breakScan()`** - Programmatically stop the current scan operation.

**Usage:**
```javascript
if (criticalError) {
    _breakScan(); // Stop scanning due to error
}
```

## Environment Information

### Mode Detection Functions

#### _isConsoleMode()
**`bool _isConsoleMode()`** - Check if running in console mode.

**Returns:** `true` if in console mode, `false` otherwise

#### _isLiteMode()
**`bool _isLiteMode()`** - Check if running in lite mode (reduced functionality).

**Returns:** `true` if in lite mode, `false` otherwise

#### _isGuiMode()
**`bool _isGuiMode()`** - Check if running with GUI interface.

**Returns:** `true` if in GUI mode, `false` otherwise

#### _isLibraryMode()
**`bool _isLibraryMode()`** - Check if running as a library component.

**Returns:** `true` if in library mode, `false` otherwise

**Example usage:**
```javascript
if (_isGuiMode()) {
    // Enable GUI-specific features
    sOptions += ", Interactive mode";
} else if (_isConsoleMode()) {
    // Console-specific optimizations
    _log("Running in console mode");
}
```

### System Information Functions

#### _getEngineVersion()
**`QString _getEngineVersion()`** - Get the Detect-It-Easy engine version.

**Returns:** Engine version string

#### _getOS()
**`QString _getOS()`** - Get the current operating system name.

**Returns:** Operating system identifier

#### _getQtVersion()
**`QString _getQtVersion()`** - Get the Qt framework version being used.

**Returns:** Qt version string

**Example usage:**
```javascript
var engineVer = _getEngineVersion();
var osName = _getOS();
var qtVer = _getQtVersion();

_log("DIE " + engineVer + " on " + osName + " (Qt " + qtVer + ")");
```