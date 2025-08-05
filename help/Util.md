# Util (Utility Functions) Class Reference

The Util class provides mathematical and utility functions for script operations, particularly useful for bit manipulation and time formatting.

## Table of Contents
- [Bit Manipulation Functions](#bit-manipulation-functions)
- [Division Functions](#division-functions)
- [Time Formatting](#time-formatting)

## Bit Manipulation Functions

### Unsigned 64-bit Shift Operations

#### shlu64()
**`quint64 shlu64(quint64 nValue, quint64 nShift)`** - Perform unsigned left bit shift on 64-bit value.

**Parameters:**
* `nValue` - The value to shift
* `nShift` - Number of positions to shift left

**Returns:** Result of left shift operation

#### shru64()
**`quint64 shru64(quint64 nValue, quint64 nShift)`** - Perform unsigned right bit shift on 64-bit value.

**Parameters:**
* `nValue` - The value to shift
* `nShift` - Number of positions to shift right

**Returns:** Result of right shift operation

### Signed 64-bit Shift Operations

#### shl64()
**`qint64 shl64(qint64 nValue, qint64 nShift)`** - Perform signed left bit shift on 64-bit value.

**Parameters:**
* `nValue` - The signed value to shift
* `nShift` - Number of positions to shift left

**Returns:** Result of signed left shift operation

#### shr64()
**`qint64 shr64(qint64 nValue, qint64 nShift)`** - Perform signed right bit shift on 64-bit value.

**Parameters:**
* `nValue` - The signed value to shift
* `nShift` - Number of positions to shift right

**Returns:** Result of signed right shift operation (arithmetic shift)

**Examples:**
```javascript
// Left shift operations
var value1 = Util.shlu64(0x12345678, 8);  // Shift left by 8 bits
var value2 = Util.shl64(-1000, 2);        // Signed left shift

// Right shift operations  
var value3 = Util.shru64(0xFFFFFFFF00000000, 32); // Unsigned right shift
var value4 = Util.shr64(-1000, 2);                // Signed arithmetic right shift

// Bit manipulation example
var extractHigh32 = Util.shru64(fullValue, 32);
var extractLow32 = fullValue & 0xFFFFFFFF;
```

## Division Functions

### divu64()
**`Util.divu64(quint64 nDividend, quint64 nDivisor)`** - Perform unsigned 64-bit division.

**Parameters:**
* `nDividend` - The unsigned dividend
* `nDivisor` - The unsigned divisor

**Returns:** Result of unsigned division

### div64()
**`Util.div64(qint64 nDividend, qint64 nDivisor)`** - Perform signed 64-bit division.

**Parameters:**
* `nDividend` - The signed dividend
* `nDivisor` - The signed divisor

**Returns:** Result of signed division

**Examples:**
```javascript
// Unsigned division
var result1 = Util.divu64(0xFFFFFFFFFFFFFFFF, 1000);

// Signed division
var result2 = Util.div64(-5000000000, 1000);

// Safe division with check
if (divisor != 0) {
    var quotient = Util.div64(dividend, divisor);
    _log("Result: " + quotient);
}
```

## Time Formatting

### secondsToTimeStr()
**`QString secondsToTimeStr(qint32 nValue)`** - Convert seconds to human-readable time string.

**Parameters:**
* `nValue` - Time value in seconds

**Returns:** Formatted time string (e.g., "1h 23m 45s")

**Examples:**
```javascript
// Format various time durations
var time1 = Util.secondsToTimeStr(3661);    // "1h 1m 1s"
var time2 = Util.secondsToTimeStr(90);      // "1m 30s"
var time3 = Util.secondsToTimeStr(45);      // "45s"

// Usage in file analysis
var timestamp = Binary.read_uint32(0x10);
if (timestamp > 0) {
    var timeStr = Util.secondsToTimeStr(timestamp);
    sOptions = "duration: " + timeStr;
}

// Calculate file processing time
var processingTime = Util.secondsToTimeStr(endTime - startTime);
_log("Processing completed in " + processingTime);
```

These utility functions are essential for low-level binary analysis and data manipulation in signature scripts.
