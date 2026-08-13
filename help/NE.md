# NE (New Executable) Class Reference

* You could use all functions from Binary class but with NE prefix (Binary.compareEP -> NE.compareEP)
* You could use all functions from MSDOS class but with NE prefix (MSDOS.isDosStubPresent -> NE.isDosStubPresent)

## File Format Detection

### Basic PE Detection

**`bool isNE16()`** - Check if the file is NE16 (16-bit) format.

**`bool isDll()`** - Check if the file is a Dynamic Link Library (DLL).

**`bool isDriver()`** - Check if the file is a device driver.

**`bool isFont()`** - Check if the file is a font.
