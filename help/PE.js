/**
 * @class
 * @classdesc This is a description of the PE class.
 */
function PE(){}
/**
 * @see Binary.calculateEntropy
 */
PE.calculateEntropy=function(nOffset,nSize){}
/**
 * @see Binary.calculateMD5
 */
PE.calculateMD5=function(nOffset,nSize){}
/**
 * Calculate the size of the headers.
 * @returns {UInt}
 */
PE.calculateSizeOfHeaders=function(){}
/**
 * @see Binary.compare
 */
PE.compare=function(sSignature,nOffset){}
/**
 * Compare (see {@link Binary.compare}) bytes at the <b>E</b>ntry <b>P</b>oint.
 * @param {String} sSignature - The signature.
 * @param {Int} [nOffset=0] - The offset from the entry point.
 * @returns {Bool}
 * @example
 * if(PE.compareEP("2C81",8))
 * {
 *     sVersion="1.98";
 * }
 *
 * if(PE.compareEP("EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24"))
 * {
 *     bDetected=1;
 * }
 */
PE.compareEP=function(sSignature,nOffset){}
/**
 * Compare (see {@link Binary.compare}) bytes at the <b>E</b>ntry <b>P</b>oint of .NET.
 * @param {String} sSignature - The signature.
 * @param {Int} [nOffset=0] - The offset from the entry point of .NET.
 * @returns {Bool}
 * @example
 * if(PE.compareEP_NET("4228070000066f09000006283800000a2a1b3004006f0000000d0000110272b9"))
 * {
 *     bDetected=1;
 *     sVersion="2.X";
 * }
 */
PE.compareEP_NET=function(sSignature,nOffset){}
/**
 * Compare bytes at the overlay.
 * @param {String} sSignature - The signature.
 * @param {Int} [nOffset=0] - The offset from the overlay.
 * @returns {Bool}
 * @example
 * if(PE.compareOverlay("';!@Install@!UTF-8!'"))
 * {
 *     bDetected=1;
 * }
 */
PE.compareOverlay=function(sSignature,nOffset){}
/**
 * @see Binary.findByte
 */
PE.findByte=function(nOffset,nSize,cValue){}
/**
 * @see Binary.findDword
 */
PE.findDword=function(nOffset,nSize,nValue){}
/**
 * @see Binary.findSignature
 * @example
 * nOffset=PE.findSignature(nOffset,1024,"'7z'BCAF271C");
 * if(nOffset!=-1)
 * {
 *     bDetected=1;
 * }
 */
PE.findSignature=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.findString
 * @example
 * nOffset=PE.findString(0,1024,"UPX!");
 * if(nOffset==-1)
 * {
 *     return;
 * }
 */
PE.findString=function(nOffset,nSize,sValue){}
/**
 * @see Binary.findWord
 */
PE.findWord=function(nOffset,nSize,sValue){}
/**
 * Get the relative virtual address (RVA) of the entry point.
 * @returns {UInt}
 * @example
 * var nSection=PE.nLastSection;
 * if(nSection>=2)
 * {
 *     if(PE.getAddressOfEntryPoint()==PE.section[nSection].VirtualAddress)
 *     {
 *         if(PE.section[nSection].Characteristics==0xe0000040)
 *         {
 *             if(PE.section[nSection-1].Characteristics==0xe0000040)
 *             {
 *                 if(PE.getNumberOfImportThunks(0)==1)
 *                 {
 *                     bDetected=1;
 *                 }
 *             }
 *         }
 *     }
 * }
 */
PE.getAddressOfEntryPoint=function(){}
/**
 * Get the compiler version.
 * @returns {String} The string <code>"<i>MajorLinkerVersion</i>.<i>MinorLinkerVersion</i>"</code>.
 * @example
 * if(bDetected)
 * {
 *     switch(PE.getCompilerVersion())
 *     {
 *     case "6.0":  sVersion="6.0";  break;
 *     case "7.0":  sVersion="2002"; break;
 *     case "7.10": sVersion="2003"; break;
 *     case "8.0":  sVersion="2005"; break;
 *     case "9.0":  sVersion="2008"; break;
 *     case "10.0": sVersion="2010"; break;
 *     case "11.0": sVersion="2012"; break;
 *     case "12.0": sVersion="2013"; break;
 *     }
 * }
 */
PE.getCompilerVersion=function(){}
/**
 * Get the number of the section containing the entry point.
 * @returns {Int} If no entry point returns <code>-1</code>.
 * @example
 * if(PE.getEntryPointSection()==PE.nLastSection)
 * {
 *     bDetected=1;
 * }
 */
PE.getEntryPointSection=function(){}
/**
 * @see Binary.getFileDirectory
 */
PE.getFileDirectory=function(){}
/**
 * Get the version of the file, if the version resource exists.
 * @returns {String}
 */
PE.getFileVersion=function(){}
/**
 * Get a string in the form of <code>"<i>PEtype</i><i>PEmode</i>"</code>. For example <samp>"EXE32"</samp> or <samp>"Driver32"</samp>.
 * @returns {String}
 */
PE.getGeneralOptions=function(){}
/**
 * Get the base address of the image.
 * @returns {UInt}
 */
PE.getImageBase=function(){}
/**
 * Get the name of an imported function.
 * @param {UInt} nImport - Number of the imported library.
 * @param {UInt} nFunctionNumber - Number of the function in the library.
 * @returns {String}
 */
PE.getImportFunctionName=function(nImport,nFunctionNumber){}
/**
 * Get the name of an imported library.
 * @param {UInt} nImport - Number of the imported library.
 * @returns {String}
 */
PE.getImportLibraryName=function(nImport){}
/**
 * Get the number of the section containing the import table.
 * @returns {Int} If no import returns <code>-1</code>.
 */
PE.getImportSection=function(){}
/**
 * Get the machine type.
 * @returns {UShort}
 */
PE.getMachineType=function(){}
/**
 * Get the major linker version.
 * @returns {UInt}
 * @example
 * var nMajor=PE.getMajorLinkerVersion();
 * if(nMajor>3)
 * {
 *     sName="Microsoft Linker";
 *     bDetected=1;
 * }
 */
PE.getMajorLinkerVersion=function(){}
/**
 * Get the XML manifest from the resources.
 * @returns {String}
 * @example
 * if(/requireAdministrator/.test(PE.getManifest()))
 * {
 *     sOptions=sOptions.append("admin");
 * }
 */
PE.getManifest=function(){}
/**
 * Get the minor linker version.
 * @returns {UInt}
 * @example
 * var nMinor=PE.getMinorLinkerVersion();
 * if(nMinor==55)
 * {
 *     sName="LCC Linker";
 *     sVersion+="*";
 *     bDetected=1;
 * }
 */
PE.getMinorLinkerVersion=function(){}
/**
 * Get the .NET version.
 * @returns {String}
 * @example
 * if(PE.isNET())
 * {
 *     sVersion=PE.getNETVersion();
 *     bDetected=1;
 * }
 */
PE.getNETVersion=function(){}
/**
 * Get the number of imports.
 * @returns {Int}
 * @example
 * if(PE.getNumberOfImports()==1)
 * {
 *     if(PE.getNumberOfImportThunks(0)==2)
 *     {
 *         if(PE.section[0].Name=="ANDpakk2")
 *         {
 *             sVersion="2.X";
 *             bDetected=1;
 *         }
 *     }
 * }
 */
PE.getNumberOfImports=function(){}
/**
 * Get the number of functions in the imported library.
 * @param {UInt} nImport - Number of the library.
 * @returns {UInt}
 * @example
 * if(PE.getNumberOfImportThunks(0)==1)
 * {
 *     bDetected=1;
 * }
 */
PE.getNumberOfImportThunks=function(nImport){}
/**
 * Get the number of sections.
 * @returns {Int}
 */
PE.getNumberOfSections=function(){}
/**
 * Get the file offset of the overlay.
 * @returns {UInt}
 */
PE.getOverlayOffset=function(){}
/**
 * Get the size of the overlay .
 * @returns {UInt}
 */
PE.getOverlaySize=function(){}
/**
 * Get the version of a particular file, if the version resource exists.
 * @param {String} sFileName - The file name.
 * @returns {String}
 */
PE.getPEFileVersion=function(sFileName){}
/**
 * Get the file offset to a named resource.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int} If an error occurs, <code>-1</code> will be returned.
 */
PE.getResourceNameOffset=function(sName){}
/**
 * Get the size of a named resource.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int}
 */
PE.getResourceNameSize=function(sName){}
/**
 * Get the characteristics of a section.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {UInt}
 */
PE.getSectionCharacteristics=function(nSectionNumber){}
/**
 * Get the file offset of a setion.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {UInt}
 */
PE.getSectionFileOffset=function(nSectionNumber){}
/**
 * Get the file size of a section.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {UInt}
 */
PE.getSectionFileSize=function(nSectionNumber){}
/**
 * Get the name of a section.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {String}
 */
PE.getSectionName=function(nSectionNumber){}
/**
 * Get the relative virtual address of a section.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {UInt}
 */
PE.getSectionVirtualAddress=function(nSectionNumber){}
/**
 * Get the virtual size of a section.
 * @param {Int} nSectionNumber - Section number (from 0).
 * @returns {UInt}
 */
PE.getSectionVirtualSize=function(nSectionNumber){}
/**
 * Get the common prefix of two section name suffixes.
 * @param {String} sString1 - First section name suffix.
 * @param {String} sString2 - Second section name suffix.
 * @returns {String} Section name prefix.
 * @example
 * if("UPX"==PE.getSectionNameCollision("0","1"))
 * {
 *     // Both "UPX0" and "UPX1" exist.
 *     bDetected=1;
 * }
 */
PE.getSectionNameCollision=function(sString1,sString2){}
/**
 * Get the number of a section with a specific name.
 * @param {String} sSectionName - Section name.
 * @returns {Int} 0-based section number, or <code>-1</code> if there is no section with that name.
 */
PE.getSectionNumber=function(sSectionName){}
/**
 * Get the number of a section whose name matches a regular expression.
 * @param {String} sSectionName - Section pattern.
 * @returns {Int} 0-based section number, or <code>-1</code> if there is no section with that pattern.
 */
PE.getSectionNumberExp=function(sSectionName){}
/**
 * Checks if a section exists with a specific name.
 * @param {String} sSectionName - Section name.
 * @returns {Bool}
 */
PE.isSectionNamePresent=function(sSectionName){}
/**
 * Check if a section name matches a regular expression.
 * @param {String} sSectionName - Section pattern.
 * @returns {Bool}
 */
PE.isSectionNamePresentExp=function(sSectionName){}
/**
 * @see Binary.getSignature
 */
PE.getSignature=function(nOffset,nSize){}
/**
 * @see Binary.getSize
 */
PE.getSize=function(){}
/**
 * Get the size of code.
 * @returns {Int}
 */
PE.getSizeOfCode=function(){}
/**
 * Get the size of unitialized data.
 * @returns {Int}
 */
PE.getSizeOfUninitializedData=function(){}
/**
 * Check if the file is a console application.
 * @returns {Bool}
 */
PE.isConsole=function(){}
/**
 * Check if the file is a DLL.
 * @returns {Bool}
 */
PE.isDll=function(){}
/**
 * Check if the file is a driver.
 * @returns {Bool}
 */
PE.isDriver=function(){}
/**
 * Check if the file is a .NET application.
 * @returns {Bool}
 */
PE.isNET=function(){}
/**
 * Check if there is an overlay in the file.
 * @returns {Bool}
 */
PE.isOverlayPresent=function(){}
/**
 * Check if the file is 64 bit (PE+).
 * @returns {Bool}
 * @example
 * if(PE.isPEPlus())
 * {
 *     sOptions="PE+";
 * }
 */
PE.isPEPlus=function(){}
/**
 * Check if the “Rich” signature is in the file. For more information see {@link http://www.ntcore.com/files/richsign.htm}. It is typical for the files made by the MS Linker.
 * @returns {Bool}
 * @example
 * if(PE.isRichSignaturePresent())
 * {
 *     sName="Microsoft Linker";
 *     bDetected=1;
 * }
 */
PE.isRichSignaturePresent=function(){}
/**
 * Check if there is a resource with a specific name in the file.
 * @param {String} sName - The name of the resource.
 * @returns {Bool}
 * @example
 * if(PE.isResourceNamePresent("PACKAGEINFO"))
 * {
 *     bDetected=1;
 * }
 */
PE.isResourceNamePresent=function(sName){}
/**
 * Check if there is a specific .NET string.
 * @param {String} sString
 * @returns {Bool}
 * @example
 * if(PE.isNETStringPresent(0,"DotfuscatorAttribute"))
 * {
 *     bDetected=1;
 * }
 */
PE.isNETStringPresent=function(sString){}
/**
 * Check if there is a specific .NET Unicode string.
 * @param {String} sString
 * @returns {Bool}
 * @example
 * if(PE.isNETUnicodeStringPresent("E_TamperDetected"))
 * {
 *     sVersion="3.X-4.X";
 *     bDetected=1;
 * }
 */
PE.isNETUnicodeStringPresent=function(sString){}
/**
 * Check if a function exists in a library.
 * @param {String} sLibraryName - The name of the library.
 * @param {String} sFunctionName - The name of the function.
 * @returns {Bool}
 */
PE.isLibraryFunctionPresent=function(sLibraryName,sFunctionName){}
/**
 * Check if a library is imported.
 * @param {String} sLibraryName - The name of the library.
 * @returns {Bool}
 * @example
 * if(PE.isLibraryPresent("MSVBVM50.DLL"))
 * {
 *     sVersion="5.0";
 *     bDetected=1;
 * }
 */
PE.isLibraryPresent=function(sLibraryName){}
/**
 * Check if a signature (see {@link Binary.compare}) exists in a section.
 * @param {Int} nSection - Section number (from 0).
 * @param {String} sSignature - Signature.
 * @returns {Bool}
 * @example
 * if(PE.isSignatureInSectionPresent(0,"'ENIGMA'"))
 * {
 *     bDetected=1;
 * }
 */
PE.isSignatureInSectionPresent=function(nSection,sSignature){}
/**
 * @see Binary.isSignaturePresent
 */
PE.isSignaturePresent=function(nOffset,nSize,sSignature){}
/**
 * Convert a file offset to a relative virtual address (RVA).
 * @param {UInt64} nOffset
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
PE.OffsetToRVA=function(nOffset){}
/**
 * Convert a file offset to a virtual address (VA).
 * @param {UInt64} nOffset
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
PE.OffsetToVA=function(nOffset){}
/**
 * @see Binary.readByte
 */
PE.readByte=function(nOffset){}
/**
 * @see Binary.readDword
 */
PE.readDword=function(nOffset){}
/**
 * @see Binary.readQword
 */
ELF.readQword=function(nOffset){}
/**
 * @see Binary.readWord
 */
PE.readWord=function(nOffset){}
/**
 * @see Binary.swapBytes
 */
PE.swapBytes=function(nValue){}
/**
 * Convert a relative virtual address (RVA) to a file offset.
 * @param {UInt64} nRVA
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
PE.RVAToOffset=function(nRVA){}
/**
 * Convert a virtual address (VA) to a file offset.
 * @param {UInt64} nVA
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
PE.VAToOffset=function(nVA){}
/**
 * @see Binary.getString
 */
PE.getString=function(nOffset,nSize){}
/**
 * Get the value associated with a version resource string key.
 * @param {String} sKey
 * @returns {String}
 */
PE.getVersionStringInfo=function(sKey){}
/**
 * Check if there is an MSDOS stub.
 * @returns {Bool}
 */
PE.isDosStubPresent=function(){}
/**
 * Get the file offset of the MSDOS stub.
 * @returns {UInt}
 */
PE.getDosStubOffset=function(){}
/**
 * Get the size of the MSDOS stub.
 * @returns {UInt}
 */
PE.getDosStubSize=function(){}
/**
 * Get the number of resources.
 * @returns {UInt}
 */
PE.getNumberOfResources=function(){}
/**
 * Get the offset of a resource.
 * @param {UInt} nNumber - Number of resource.
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.getResourceOffsetByNumber=function(nNumber){}
/**
 * Get the size of a resource.
 * @param {UInt} nNumber - Number of resource.
 * @returns {Int}
 */
PE.getResourceSizeByNumber=function(nNumber){}
/**
 * Get the Id of a resource.
 * @param {UInt} nNumber - Number of resource.
 * @returns {UInt}
 */
PE.getResourceIdByNumber=function(nNumber){}
/**
 * Get the name of a resource.
 * @param {UInt} nNumber - Number of resource.
 * @returns {String}
 */
PE.getResourceNameByNumber=function(nNumber){}
/**
 * Get the type of a resource.
 * @param {UInt} nNumber - Number of resource.
 * @returns {String}
 * @example
 * if(PE.getResourceTypeByNumber(0)=="RT_MANIFEST")
 * {
 *     bDetected=1;
 * }
 */
PE.getResourceTypeByNumber=function(nNumber){}
/**
 * Get the number of the section containing the export table.
 * @returns {Int} If no export returns <code>-1</code>.
 */
PE.getExportSection=function(){}
/**
 * Get the number of the section containing the relocations.
 * @returns {Int} If no relocations returns <code>-1</code>.
 */
PE.getRelocsSection=function(){}
/**
 * Get the number of the section containing the resources.
 * @returns {Int} If no resources returns <code>-1</code>.
 */
PE.getResourceSection=function(){}
/**
 * Get the number of the section containing the TLS.
 * @returns {Int} If no TLS returns <code>-1</code>.
 */
PE.getTLSSection=function(){}
/**
 * Get the number of the Rich IDs.
 * @returns {UInt}
 */
PE.getNumberOfRichIDs=function(){}
/**
 * Check if there is a Rich version.
 * @param {UInt} nVersion - Rich version.
 * @returns {Bool}
 */
PE.isRichVersionPresent=function(nVersion){}
/**
 * Check if there is a digital signature.
 * @returns {Bool}
 */
PE.isSignedFile=function(){}
/**
 * Get the offset of the entry point.
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
PE.getEntryPointOffset=function(){}
/**
 * @see Binary.getFileBaseName
 */
PE.getFileBaseName=function(){}
/**
 * @see Binary.getFileSuffix
 */
PE.getFileSuffix=function(){}
/**
 * @see Binary.getFileCompleteSuffix
 */
PE.getFileCompleteSuffix=function(){}
/**
 * Check if Export presents.
 * @returns {Bool}
 */
PE.isExportPresent=function(){}
/**
 * Check if TLS presents.
 * @returns {Bool}
 */
PE.isTLSPresent=function(){}
/**
 * Check if Import presents.
 * @returns {Bool}
 */
PE.isImportPresent=function(){}
/**
 * Check if Resource presents.
 * @returns {Bool}
 */
PE.isResourcePresent=function(){}
/**
 * Check if Export function exists with a specific name.
 * @param {String} sFunctionName - Function name
 * @returns {Bool}
 */
PE.isExportFunctionPresent=function(){}
/**
 * Check if Export function matches a regular expression.
 * @param {String} sFunctionName - Function pattern
 * @returns {Bool}
 */
PE.isExportFunctionPresentExp=function(){}
