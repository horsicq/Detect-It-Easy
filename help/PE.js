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
 * The function compares bytes 
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset in the file. By default is 0.
 * @returns {Bool} 
 */
PE.compareEP=function(sSignature,nOffset){};
PE.compareEP_NET=function(sSignature,nOffset){};
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
PE.getAddressOfEntryPoint=function(){};
PE.getCompilerVersion=function(){};
PE.getEntryPointSection=function(){};
/**
 * @see {@link Binary.getFileDirectory}
 */
PE.getFileDirectory=function(){};
PE.getFileVersion=function(){};
PE.getGeneralOptions=function(){};
PE.getImageBase=function(){};
PE.getImportFunctionName=function(nImport,nFunctionNumber){};
PE.getImportLibraryName=function(nImport){};
PE.getImportSection=function(){};
PE.getMachineType=function(){};
PE.getMajorLinkerVersion=function(){};
PE.getManifest=function(){};
PE.getMinorLinkerVersion=function(){};
PE.getNETVersion=function(){};
PE.getNumberOfImports=function(){};
PE.getNumberOfImportThunks=function(nImport){};
PE.getNumberOfSections=function(){};
PE.getOverlayOffset=function(){};
PE.getOverlaySize=function(){};
PE.getPEFileVersion=function(sFileName){};
PE.getResourceNameOffset=function(sName){};
PE.getResourceNameSize=function(sName){};
PE.getSectionCharacteristics=function(nSectionNumber){};
PE.getSectionFileOffset=function(nSectionNumber){};
PE.getSectionFileSize=function(nSectionNumber){};
PE.getSectionName=function(nSectionNumber){};
PE.getSectionVirtualAddress=function(nSectionNumber){};
PE.getSectionVirtualSize=function(nSectionNumber){};
PE.getSectionNameCollision=function(sString1,sString2){};
PE.getSectionNumber=function(sSectionName){};
PE.getSectionNumberExp=function(sSectionName){};
PE.isSectionNamePresent=function(sSectionName){};
PE.isSectionNamePresentExp=function(sSectionName){};
/**
 * @see {@link Binary.getSize}
 */
PE.getSize=function(){};
PE.getSizeOfCode=function(){};
PE.getSizeOfUninitializedData=function(){};
PE.isConsole=function(){};
PE.isDll=function(){};
PE.isNET=function(){};
PE.isOverlayPresent=function(){};
PE.isPEPlus=function(){};
PE.isRichSignaturePresent=function(){};
PE.isResourceNamePresent=function(sName){};
PE.isNETStringPresent=function(sString){};
PE.isNETUnicodeStringPresent=function(sString){};
PE.isLibraryFunctionPresent=function(sLibraryName,sFunctionName){};
PE.isLibraryPresent=function(sLibraryName){};
PE.isSignatureInSectionPresent=function(nSection,sSignature){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
PE.isSignaturePresent=function(nOffset,nSize,sSignature){};
PE.OffsetToRVA=function(nOffset){};
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
PE.RVAToOffset=function(nRVA){};
PE.VAToOffset=function(nVA){};
/**
 * @see {@link Binary.getString}
 */
PE.getString=function(nOffset,nSize){};
PE.getVersionStringInfo=function(sKey){};