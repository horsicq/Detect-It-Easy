###This is a description of the Binary class. This class is used when no other class matches.

**qint64 getSize()** Get the size of the file

```
```
**bool compare(QString sSignature,qint64 nOffset=0)**

```
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
**double calculateEntropy(qint64 nOffset,qint64 nSize)**

```
```
**QString calculateMD5(qint64 nOffset,qint64 nSize)**

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