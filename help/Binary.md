This is a description of the Binary class. This class is used when no other class matches.

**qint64 getSize()** Get the size of the file

```
```
**bool compare(QString sSignature,qint64 nOffset=0)** Compares bytes with a hexadecimal string signature.

The signature may contain both lowercase and uppercase hexadecimal digits.
Spaces are skipped, and . and ? represent any digit.
Text may be matched by using single quotes. For example **"01'Test'01"**.

There are two additional symbols:

* '#' for absolute jump (e.g. "68########55")
* '$' for relative jump (e.g. "E8$$$$$$$$55")

```
if(Binary.compare("'7z'BCAF271C")) // compare file header (nOffset=0)
{
    sVersion=Binary.readByte(6)+"."+Binary.readByte(7);
    bDetected=1;
}
 
if(Binary.compare("'WAVEfmt '",8)) // compare file from offset 8
{
    bDetected=1;
}
```
**bool compareEP(QString sSignature,qint64 nOffset=0)** Compare bytes at the Entry Point.

* sSignature - The signature.
* nOffset - The offset from the entry point.

```
if(PE.compareEP("2C81",8))
{
    sVersion="1.98";
}

if(PE.compareEP("EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24"))
{
    bDetected=1;
}
```
**quint8 readByte(qint64 nOffset)** Read a byte value from the file.

```
```
**qint8 readSByte(qint64 nOffset)** Read a signed byte value from the file.

```
```
**quint16 readWord(qint64 nOffset)** Read a word from the file.

```
```
**qint16 readSWord(qint64 nOffset)** Read a signed word from the file.

```
```
**quint32 readDword(qint64 nOffset)** Read a qword value from the file.

```
```
**qint32 readSDword(qint64 nOffset)** Read a signed qword value from the file.

```
```
**quint64 readQword(qint64 nOffset)** Read a qword value from the file.

```
```
**qint64 readSQword(qint64 nOffset)** Read a signed qword value from the file.

```
```
**QString getString(qint64 nOffset,qint64 nMaxSize=50)** Get a text string from the file. A string is read up to the first unreadable character or up to the maximum length.

* nOffset - The offset in the file.
* nMaxSize - The maximum size of the string, in bytes.

```
var sString=Binary.getString(0x100,32); // read a string from offset 0x100, maximum length 32 bytes
var sString=Binary.getString(60); // read a string from offset 60, maximum length 50 bytes (default value)
```
**qint64 findSignature(qint64 nOffset,qint64 nSize,QString sSignature)** Search for a signature in the file.

* Returns Offset in the file if the value is found; **-1** otherwise.

```
```
**qint64 findString(qint64 nOffset,qint64 nSize,QString sString)** Search for a string in the file.

* Returns Offset in the file if the value is found; **-1** otherwise.

```
```
**qint64 findByte(qint64 nOffset,qint64 nSize,quint8 nValue)** Search for a byte in the file.

* Returns Offset in the file if the value is found; **-1** otherwise.

```
```
**qint64 findWord(qint64 nOffset,qint64 nSize,quint16 nValue)** Search for a word in the file.

* Returns Offset in the file if the value is found; **-1** otherwise.

```
```
**qint64 findDword(qint64 nOffset,qint64 nSize,quint32 nValue)** Search for a dword in the file.

* Returns Offset in the file if the value is found; **-1** otherwise.

```
```
**qint64 getEntryPointOffset()**

```
```
**qint64 getOverlayOffset()**

```
```
**qint64 getOverlaySize()**

```
```
**qint64 getAddressOfEntryPoint()**

```
```
**bool isOverlayPresent()**

```
```
**bool compareOverlay(QString sSignature,qint64 nOffset=0)**

```
```
**bool isSignaturePresent(qint64 nOffset,qint64 nSize,QString sSignature)** Check if a signature (see {@link Binary.compare compare}) exists in a region of the file.

```
```
**quint32 swapBytes(quint32 nValue)** Swap the four bytes of a dword. 

For example **0x11223344** becomes **0x44332211**.

```
```

**qint64 RVAToOffset(qint64 nRVA)**

```
```
**qint64 VAToOffset(qint64 nVA)**

```
```
**qint64 OffsetToVA(qint64 nOffset)**

```
```
**qint64 OffsetToRVA(qint64 nOffset)**

```
```
**QString getFileDirectory()** Get the directory of the file.

```
```
**QString getFileBaseName()** Get the base name of the file.

```
```
**QString getFileCompleteSuffix()** Get the complete suffix of the file.

```
```
**QString getFileSuffix()** Get the suffix of the file.

```
```
**QString getSignature(qint64 nOffset,qint64 nSize)** Get a signature string from the file.

```
var signature=Binary.getSignature(0,4);
if(signature=="AA5411DD")
{
    bDetected=1;
}
```
**double calculateEntropy(qint64 nOffset,qint64 nSize)** Calculate the entropy of a region of the file.

* Result in the form of quantity of bits per byte. Since there are 8 bits in a byte, the maximum entropy will be 8.0.

```
```
**QString calculateMD5(qint64 nOffset,qint64 nSize)** Calculate the MD5 hash of a region of the file.

```
```
**bool isSignatureInSectionPresent(quint32 nNumber,QString sSignature)**

```
```
**qint64 getImageBase()**

```
```
**QString upperCase(QString sString)**

```
```
**QString lowerCase(QString sString)**

```
```
**bool isPlainText()**

```
```
**qint32 getDisasmLength(qint64 nAddress)**

```
```
**QString getDisasmString(qint64 nAddress)**

```
```
**qint64 getDisasmNextAddress(qint64 nAddress)**

```
```
**bool is16()**

```
```
**bool is32()**

```
```
**bool is64()**

```
```