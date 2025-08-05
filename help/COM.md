# COM (MS-DOS COM Executable) Class Reference

The COM class provides analysis capabilities for MS-DOS COM (Command) executable files, which are simple binary executables that load at a fixed memory address.

## Inheritance
* **Inherits from Binary class** - All Binary class functions are available with COM prefix (e.g., `Binary.compareEP` → `COM.compareEP`)

## Overview

COM files are the simplest form of executable files in MS-DOS. They:
- Have no header structure
- Load at memory address 0x0100 
- Are limited to 64KB in size
- Execute directly from the first byte

## Detection

COM files are typically detected by:
1. File extension (.COM)
2. File size (≤ 65,280 bytes)
3. Executable code patterns at the beginning
4. Absence of other executable headers (PE, NE, etc.)

## Usage Examples

```javascript
// Basic COM file detection
if (Binary.getSize() <= 65280 && Binary.getSize() > 0) {
    // Check for common COM file patterns
    if (COM.compare("E9") ||           // JMP near
        COM.compare("EB") ||           // JMP short  
        COM.compare("B4") ||           // MOV AH, immediate
        COM.compare("CD21")) {         // INT 21h
        sName = "MS-DOS COM executable";
        bDetected = true;
    }
}

// Check for specific COM program signatures
if (COM.compare("E9....")) {
    // Jump instruction at start
    sOptions = "JMP start";
} else if (COM.compare("B409CD21")) {
    // Print string DOS call
    sOptions = "DOS text output";
}
```

Since COM files inherit all Binary class functionality, you can use advanced analysis methods:

```javascript
// Analyze entropy to detect packed COM files
var entropy = COM.calculateEntropy(0, COM.getSize());
if (entropy > 7.5) {
    sOptions = "possibly packed";
}

// Search for DOS API calls
if (COM.findSignature(0, COM.getSize(), "CD21") != -1) {
    sOptions = "uses DOS API";
}
```
