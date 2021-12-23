###This is a description of the PE class.

* You could use all functions from Binary class but with PE prefix (Binary.compareEP -> PE.compareEP)
* You could use all functions from MSDOS class but with PE prefix (MSDOS.isDosStubPresent -> PE.isDosStubPresent)

**quint16 getNumberOfSections()**

```
```
**QString getSectionName(quint32 nNumber)**

```
```
**quint32 getSectionVirtualSize(quint32 nNumber)**

```
```
**quint32 getSectionVirtualAddress(quint32 nNumber)**

```
```
**quint32 getSectionFileSize(quint32 nNumber)**

```
```
**quint32 getSectionFileOffset(quint32 nNumber)**

```
```
**quint32 getSectionCharacteristics(quint32 nNumber)**

```
```
**quint32 getNumberOfResources()**

```
```
**bool isSectionNamePresent(QString sSectionName)**

```
```
**bool isSectionNamePresentExp(QString sSectionName)**

```
```
**bool isNET()**

```
```
**bool isPEPlus()**

```
```
**virtual QString getGeneralOptions()**

```
```
**quint32 getResourceIdByNumber(quint32 nNumber)**

```
```
**QString getResourceNameByNumber(quint32 nNumber)**

```
```
**qint64 getResourceOffsetByNumber(quint32 nNumber)**

```
```
**qint64 getResourceSizeByNumber(quint32 nNumber)**

```
```
**quint32 getResourceTypeByNumber(quint32 nNumber)**

```
```
**bool isNETStringPresent(QString sString)**

```
```
**bool isNETUnicodeStringPresent(QString sString)**

```
```
**qint32 getNumberOfImports()**

```
```
**QString getImportLibraryName(quint32 nNumber)**

```
```
**bool isLibraryPresent(QString sLibraryName)**

```
```
**bool isLibraryFunctionPresent(QString sLibraryName,QString sFunctionName)**

```
```
**QString getImportFunctionName(quint32 nImport,quint32 nFunctionNumber)**

```
```
**qint32 getImportSection()**

```
```
**qint32 getExportSection()**

```
```
**qint32 getResourceSection()**

```
```
**qint32 getEntryPointSection()**

```
```
**qint32 getRelocsSection()**

```
```
**qint32 getTLSSection()**

```
```
**quint8 getMajorLinkerVersion()**

```
```
**quint8 getMinorLinkerVersion()**

```
```
**QString getManifest()**

```
```
**QString getVersionStringInfo(QString sKey)**

```
```
**qint32 getNumberOfImportThunks(quint32 nNumber)**

```
```
**qint64 getResourceNameOffset(QString sName)**

```
```
**bool isResourceNamePresent(QString sName)**

```
```
**bool isResourceGroupNamePresent(QString sName)**

```
```
**bool isResourceGroupIdPresent(quint32 nID)**

```
```
**QString getCompilerVersion()**

```
```
**bool isConsole()**

```
```
**bool isSignedFile()**

```
```
**QString getSectionNameCollision(QString sString1,QString sString2)**

```
```
**qint32 getSectionNumber(QString sSectionName)**

```
```
**qint32 getSectionNumberExp(QString sSectionName)**

```
```
**bool isDll()**

```
```
**bool isDriver()**

```
```
**QString getNETVersion()**

```
```
**bool compareEP_NET(QString sSignature,qint64 nOffset=0)**

```
```
**quint32 getSizeOfCode()**

```
```
**quint32 getSizeOfUninitializedData()**

```
```
**QString getPEFileVersion(QString sFileName)**

```
```
**QString getFileVersion()**

```
```
**QString getFileVersionMS()**

```
```
**qint64 calculateSizeOfHeaders()**

```
```
**bool isExportFunctionPresent(QString sFunctionName)**

```
```
**bool isExportFunctionPresentExp(QString sFunctionName)**

```
```
**bool isExportPresent()**

```
```
**bool isTLSPresent()**

```
```
**bool isImportPresent()**

```
```
**bool isResourcesPresent()**

```
```
**quint32 getImportHash32()**

```
```
**quint64 getImportHash64()**

```
```
**bool isImportPositionHashPresent(qint32 nIndex,quint32 nHash)**

```
```

