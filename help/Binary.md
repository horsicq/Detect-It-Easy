###This is a description of the Binary class. This class is used when no other class matches.

**qint64 getSize()** Get the size of the file

```
```
**bool compare(QString sSignature,qint64 nOffset=0)** Compares bytes with a hexadecimal string signature.

The signature may contain both lowercase and uppercase hexadecimal digits.
Spaces are skipped, and <code>.</code> and <code>?</code> represent any digit.
Text may be matched by using single quotes. For example <samp>"01'Test'01"</samp>.

There are two additional symbols:

* # for absolute jump (e.g. "68########55")
* $ for relative jump (e.g. "E8$$$$$$$$55")

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
**bool compareEP(QString sSignature,qint64 nOffset=0)**

```
```
**quint8 readByte(qint64 nOffset)**

```
```
**qint8 readSByte(qint64 nOffset)**

```
```
**quint16 readWord(qint64 nOffset)**

```
```
**qint16 readSWord(qint64 nOffset)**

```
```
**quint32 readDword(qint64 nOffset)**

```
```
**qint32 readSDword(qint64 nOffset)**

```
```
**quint64 readQword(qint64 nOffset)**

```
```
**qint64 readSQword(qint64 nOffset)**

```
```
**QString getString(qint64 nOffset,qint64 nMaxSize=50)**

```
```
**qint64 findSignature(qint64 nOffset,qint64 nSize,QString sSignature)**

```
```
**qint64 findString(qint64 nOffset,qint64 nSize,QString sString)**

```
```
**qint64 findByte(qint64 nOffset,qint64 nSize,quint8 nValue)**

```
```
**qint64 findWord(qint64 nOffset,qint64 nSize,quint16 nValue)**

```
```
**qint64 findDword(qint64 nOffset,qint64 nSize,quint32 nValue)**

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
**bool isSignaturePresent(qint64 nOffset,qint64 nSize,QString sSignature)**

```
```
**quint32 swapBytes(quint32 nValue)**

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
**QString getFileDirectory()**

```
```
**QString getFileBaseName()**

```
```
**QString getFileCompleteSuffix()**

```
```
**QString getFileSuffix()**

```
```
**QString getSignature(qint64 nOffset,qint64 nSize)**

```
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