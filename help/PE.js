/**
 * @class
 * @classdesc This is a description of the PE class.
 */
function PE(){};
/**
 * Calculate size of headers
 * @returns {UInt} 
 */
PE.calculateSizeOfHeaders=function(){};
/**
 * @see {@link Binary.compare}
 */
PE.compare=function(sSignature,nOffset){};
/**
 * The function compares bytes at the EntryPoint 
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the EntryPoint. By default is 0.
 * @returns {Bool} 
 */
PE.compareEP=function(sSignature,nOffset){};
/**
 * The function compares bytes at the EntryPoint of .NET
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the EntryPoint of .NET. By default is 0.
 * @returns {Bool} 
 */
PE.compareEP_NET=function(sSignature,nOffset){};
/**
 * The function compares bytes of overlay
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the overlay offset. By default is 0.
 * @returns {Bool} 
 */
PE.compareOverlay=function(sSignature,nOffset){};
/**
 * @see {@link Binary.findByte}
 */
PE.findByte=function(nOffset,nSize,cValue){};
/**
 * @see {@link Binary.findDword}
 */
PE.findDword=function(nOffset,nSize,nValue){};
/**
 * @see {@link Binary.findSignature}
 */
PE.findSignature=function(nOffset,nSize,Signature){};
/**
 * @see {@link Binary.findString}
 */
PE.findString=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.findWord}
 */
PE.findWord=function(nOffset,nSize,sValue){};
/**
 * Get address of EntryPoint
 * @returns {UInt} 
 */
PE.getAddressOfEntryPoint=function(){};
/**
 * Get compiler version.
 * @returns {String} The function returns the string <MajorLinkerVersion >.< MinorLinkerVersion >
 */
PE.getCompilerVersion=function(){};
/**
 * The function returns the number of a section, where the point of entry is located (address of entry point) (0…N)
 * @returns {Int} if no entry point returns -1
 */
PE.getEntryPointSection=function(){};
/**
 * @see {@link Binary.getFileDirectory}
 */
PE.getFileDirectory=function(){};
/**
 * This function returns the version of the opened file. If the version can be found in the resources.
 * @returns {String}
 */
PE.getFileVersion=function(){};
/**
 * This function returns a string in the form of <PEtype><PEmоde> For example EXE32 or Driver32
 * @returns {String}
 */
PE.getGeneralOptions=function(){};
/**
 * Get image base
 * @returns {UInt} 
 */
PE.getImageBase=function(){};
/**
 * This function returns the name of the imported function.
 * @param {UInt} nImport - The sequence number of the imported library (0…N).
 * @param {UInt} nFunctionNumber - The sequence number of the function in the library (0…N)
 * @returns {String}
 */
PE.getImportFunctionName=function(nImport,nFunctionNumber){};
/**
 * This function returns the name of the imported library.
 * @param {UInt} nImport - The sequence number of the imported library (0…N).
 * @returns {String}
 */
PE.getImportLibraryName=function(nImport){};
/**
 * The function returns the number of a section, where the import is located (address of entry point) (0…N)
 * @returns {Int} if no import returns -1
 */
PE.getImportSection=function(){};
/**
 * Get machine type
 * @returns {UShort} 
 */
PE.getMachineType=function(){};
/**
 * Get major linker version
 * @returns {UInt} 
 */
PE.getMajorLinkerVersion=function(){};
/**
 * This XML manifest from the resources.
 * @returns {String}
 */
PE.getManifest=function(){};
/**
 * Get minor linker version
 * @returns {UInt} 
 */
PE.getMinorLinkerVersion=function(){};
/**
 * This .NET version.
 * @returns {String}
 */
PE.getNETVersion=function(){};
/**
 * Get number of imports
 * @returns {Int} 
 */
PE.getNumberOfImports=function(){};
/**
 * This function returns the number of functions in the imported library.  
 * @param {UInt} nImport - The sequence number of the imported library (0…N).
 * @returns {UInt}
 */
PE.getNumberOfImportThunks=function(nImport){};
/**
 * Get number of sections
 * @returns {Int} 
 */
PE.getNumberOfSections=function(){};
/**
 * Get overlay offset
 * @returns {UInt} 
 */
PE.getOverlayOffset=function(){};
/**
 * Get overlay size
 * @returns {UInt} 
 */
PE.getOverlaySize=function(){};
/**
 * This function returns the version of the file. If the version can be found in resources. 
 * @param {String} sFileName - The file name.
 * @returns {String}
 */
PE.getPEFileVersion=function(sFileName){};
/**
 * This function returns a offset to resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.getResourceNameOffset=function(sName){};
/**
 * This function returns a size of resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int} 
 */
PE.getResourceNameSize=function(sName){};
/**
 * 
 * @param {Int} nSectionNumber - Section number
 * @returns {String} 
 */
PE.getSectionCharacteristics=function(nSectionNumber){};
/**
 * Get section characteristics
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionFileOffset=function(nSectionNumber){};
/**
 * Get section file offset
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionFileSize=function(nSectionNumber){};
/**
 * Get section name
 * @param {Int} nSectionNumber - Section number
 * @returns {String} 
 */
PE.getSectionName=function(nSectionNumber){};
/**
 * Get section virtual address
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionVirtualAddress=function(nSectionNumber){};
/**
 * Get section virtual size
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionVirtualSize=function(nSectionNumber){};
/**
 * If the file contains sections with names “UPX0”, “UPX1”, this function  will return the string "UPX"
 * @param {String} sString1 - Section name 1.
 * @param {String} sString2 - Section name 2.
 * @returns {String} If there is no section with such name, -1 will be returned.
 */
PE.getSectionNameCollision=function(sString1,sString2){};
/**
 * This function returns the number of a section with a specific name (0-N) 
 * @param {String} sSectionName - Section name.
 * @returns {String} If there is no section with such name, -1 will be returned.
 */
PE.getSectionNumber=function(sSectionName){};
/**
 * This function returns the number of a section with a specific name (0-N). Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name.
 * @returns {String} If there is no section with such name, -1 will be returned.
 */
PE.getSectionNumberExp=function(sSectionName){};
/**
 * This function checks whether there exists a section with a specific name.
 * @param {String} sSectionName - Section name.
 * @returns {Bool} 
 */
PE.isSectionNamePresent=function(sSectionName){};
/**
 * This function checks whether there exists a section with a specific name. Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name.
 * @returns {Bool} 
 */
PE.isSectionNamePresentExp=function(sSectionName){};
/**
 * @see {@link Binary.getSize}
 */
PE.getSize=function(){};
/**
 * Get size of code
 * @returns {Int} 
 */
PE.getSizeOfCode=function(){};
/**
 * Get size of unitialized data
 * @returns {Int} 
 */
PE.getSizeOfUninitializedData=function(){};
/**
 * This function checks whether the file is a console application.
 * @returns {Bool} 
 */
PE.isConsole=function(){};
/**
 * This function checks whether the file is a DLL
 * @returns {Bool} 
 */
PE.isDll=function(){};
/**
 * This function checks whether the file is a .NET application.
 * @returns {Bool} 
 */
PE.isNET=function(){};
/**
 * This function checks whether there is an overlay in the file.
 * @returns {Bool} 
 */
PE.isOverlayPresent=function(){};
/**
 * This function checks whether the file is 64 bit (PE+)
 * @returns {Bool} 
 */
PE.isPEPlus=function(){};
/**
 * This function checks whether there is a Rich signature in the file. For more information check {@link http://www.ntсоre.соm/files/riсhsign.htm|http://www.ntсоre.соm/files/riсhsign.htm} It is typical for the files made by using the MS Linker. 
 * @returns {Bool} 
 */
PE.isRichSignaturePresent=function(){};
/**
 * This function checks whether there is a resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource.
 * @returns {Bool} 
 */
PE.isResourceNamePresent=function(sName){};
/**
 * This function checks whether there is a string with a specific name in .NET.
 * @param {String} sString
 * @returns {Bool} 
 */
PE.isNETStringPresent=function(sString){};
/**
 * This function checks whether there is a unicode string with a specific name in .NET.
 * @param {String} sString
 * @returns {Bool} 
 */
PE.isNETUnicodeStringPresent=function(sString){};
/**
 * This function checks whether there is a function with a specific name in the import.
 * @param {String} sLibraryName - The name of the library.
 * @param {String} sFunctionName - The name of the function.
 * @returns {Bool} 
 */
PE.isLibraryFunctionPresent=function(sLibraryName,sFunctionName){};
/**
 * This function checks whether there is a library with a specific name in the import.
 * @param {String} sLibraryName - The name of the library.
 * @returns {Bool} 
 */
PE.isLibraryPresent=function(sLibraryName){};
/**
 * This function checks whether there is a signature int the section.
 * @param {Int} nSection - Section number.
 * @param {String} sSignature - Signature.
 * @returns {Bool} 
 */
PE.isSignatureInSectionPresent=function(nSection,sSignature){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
PE.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * This function converts a file offset to a relative virtual address. 
 * @param {UInt} nOffset 
 * @returns {UInt} 
 */
PE.OffsetToRVA=function(nOffset){};
/**
 * This function converts a file offset to a virtual address. 
 * @param {UInt} nOffset 
 * @returns {UInt} 
 */
PE.OffsetToVA=function(nOffset){};
/**
 * @see {@link Binary.readByte}
 */
PE.readByte=function(nOffset){};
/**
 * @see {@link Binary.readDword}
 */
PE.readDword=function(nOffset){};
/**
 * @see {@link Binary.readWord}
 */
PE.readWord=function(nOffset){};
/**
 * This function converts a relative virtual address to a file offset. 
 * @param {UInt} nRVA 
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.RVAToOffset=function(nRVA){};
/**
 * This function converts a virtual address to a file offset. 
 * @param {UInt} nVA 
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.VAToOffset=function(nVA){};
/**
 * @see {@link Binary.getString}
 */
PE.getString=function(nOffset,nSize){};
/**
 * Get VersionString info
 * @param {String} sKey 
 * @returns {String} 
 */
PE.getVersionStringInfo=function(sKey){};