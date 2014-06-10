/**
 * @class
 * @classdesc This is a description of the MACH class.
 */
function MACH(){};
/**
 * @see {@link Binary.compare}
 */
MACH.compare=function(sSignature,nOffset){};
/**
 * @see {@link Binary.findByte}
 */
MACH.findByte=function(nOffset,nSize,cValue){};
/**
 * @see {@link Binary.findDword}
 */
MACH.findDword=function(nOffset,nSize,nValue){};
/**
 * @see {@link Binary.findSignature}
 */
MACH.findSignature=function(nOffset,nSize,Signature){};
/**
 * @see {@link Binary.findString}
 */
MACH.findString=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.findWord}
 */
MACH.findWord=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.getSize}
 */
MACH.getSize=function(){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
MACH.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * @see {@link Binary.readByte}
 */
MACH.readByte=function(nOffset){};
/**
 * @see {@link Binary.readDword}
 */
MACH.readDword=function(nOffset){};
/**
 * @see {@link Binary.readWord}
 */
MACH.readWord=function(nOffset){};
/**
 * @see {@link Binary.getString}
 */
MACH.getString=function(nOffset,nSize){};
/**
 * @see {@link Binary.getFileDirectory}
 */
MACH.getFileDirectory=function(){};
MACH.getGeneralOptions=function(){};
MACH.getLibraryCurrentVersion=function(sLibrary){};
MACH.getNumberOfSections=function(){};
MACH.isLibraryPresent=function(sLibrary){};
MACH.isSectionNamePresent=function(sSectionName){};