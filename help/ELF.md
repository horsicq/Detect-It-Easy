###This is a description of the ELF class.

* You could use all functions from Binary class but with ELF prefix (Binary.compareEP -> ELF.compareEP)

**bool isSectionNamePresent(QString sSectionName)**

```
```
**quint32 getNumberOfSections()**

```
```
**quint32 getNumberOfPrograms()**

```
```
**QString getGeneralOptions()**

```
```
**qint32 getSectionNumber(QString sSectionName)**

```
```
**quint16 getElfHeader_type()**

```
```
**quint16 getElfHeader_machine()**

```
```
**quint32 getElfHeader_version()**

```
```
**quint64 getElfHeader_entry()**

```
```
**quint64 getElfHeader_phoff()**

```
```
**quint64 getElfHeader_shoff()**

```
```
**quint32 getElfHeader_flags()**

```
```
**quint16 getElfHeader_ehsize()**

```
```
**quint16 getElfHeader_phentsize()**

```
```
**quint16 getElfHeader_phnum()**

```
```
**quint16 getElfHeader_shentsize()**

```
```
**quint16 getElfHeader_shnum()**

```
```
**quint16 getElfHeader_shstrndx()**

```
```
**quint64 getProgramFileSize(quint32 nNumber)**

```
```
**quint64 getProgramFileOffset(quint32 nNumber)**

```
```
**quint64 getSectionFileOffset(quint32 nNumber)**

```
```
**quint64 getSectionFileSize(quint32 nNumber)**

```
```
**bool isStringInTablePresent(QString sSectionName,QString sString)**

```
```
**bool isLibraryPresent(QString sLibraryName)**

```
```
**QString getRunPath()**


```
```
