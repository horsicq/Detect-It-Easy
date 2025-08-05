# Archive Class Reference

The Archive class provides specialized analysis capabilities for archive file formats such as ZIP, RAR, 7-Zip, and other compressed archive types.

## Inheritance
* **Inherits from Binary class** - All Binary class functions are available with Archive prefix (e.g., `Binary.compare` → `Archive.compare`)

## Table of Contents
- [Archive Record Detection](#archive-record-detection)
- [Usage Examples](#usage-examples)

## Archive Record Detection

### isArchiveRecordPresent()
**`bool isArchiveRecordPresent(QString sArchiveRecord)`** - Check if a specific archive record or file entry is present.

**Parameters:**
* `sArchiveRecord` - The archive record/filename to search for

**Returns:** `true` if the archive record exists, `false` otherwise

This function searches for specific files or entries within the archive structure.

### isArchiveRecordPresentExp()
**`bool isArchiveRecordPresentExp(QString sArchiveRecord)`** - Check if an archive record matching a pattern is present.

**Parameters:**
* `sArchiveRecord` - Pattern or expression to match against archive records

**Returns:** `true` if a matching archive record exists, `false` otherwise

This function supports pattern matching for more flexible archive content detection.

## Usage Examples

```javascript
// Check for specific files in archive
if (Archive.isArchiveRecordPresent("setup.exe")) {
    sName = "Software installer archive";
    bDetected = true;
}

// Look for configuration files
if (Archive.isArchiveRecordPresent("config.xml") || 
    Archive.isArchiveRecordPresent("settings.ini")) {
    sOptions = "contains configuration";
}

// Pattern matching for file types
if (Archive.isArchiveRecordPresentExp("*.dll")) {
    sOptions = "contains DLL files";
} else if (Archive.isArchiveRecordPresentExp("*.exe")) {
    sOptions = "contains executables";
}

// Detect specific software packages
if (Archive.isArchiveRecordPresent("META-INF/MANIFEST.MF")) {
    sName = "Java JAR archive";
    bDetected = true;
} else if (Archive.isArchiveRecordPresent("AndroidManifest.xml")) {
    sName = "Android APK package";
    bDetected = true;
}

// Check for malware indicators
if (Archive.isArchiveRecordPresentExp("*.scr") || 
    Archive.isArchiveRecordPresentExp("*.pif")) {
    sOptions = "suspicious file types";
}
```

Archive detection can be combined with Binary class methods for comprehensive analysis:

```javascript
// Analyze archive structure and content
if (Archive.compare("'PK'0304")) {
    sName = "ZIP-based archive";
    
    // Check specific content
    if (Archive.isArchiveRecordPresent("word/document.xml")) {
        sName = "Microsoft Word document";
        sFormat = "DOCX";
    } else if (Archive.isArchiveRecordPresent("xl/workbook.xml")) {
        sName = "Microsoft Excel spreadsheet";
        sFormat = "XLSX";
    }
    
    bDetected = true;
}
```
