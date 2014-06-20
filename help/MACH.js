/**
 * @class
 * @classdesc This is a description of the MACH class.
 */
function MACH(){};
/**
 * @see {@link Binary.calculateEntropy}
 */
MACH.calculateEntropy=function(nOffset,nSize){};
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
 * @see {@link Binary.getSignature}
 */
MACH.getSignature=function(){};
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
/**
 * This function returns a string in the form of [MACHtype][MACHmоde]
 * @returns {String}
 */
MACH.getGeneralOptions=function(){};
/**
 * Get library current version.
 * @param {String} sLibrary - The name of the library.
 * @returns {String} 
 */
MACH.getLibraryCurrentVersion=function(sLibrary){};
/**
 * Get number of sections
 * @returns {Int} 
 */
MACH.getNumberOfSections=function(){};
/**
 * This function checks whether there is a library with a specific name in the import.
 * @param {String} sLibraryName - The name of the library.
 * @returns {Bool} 
 */
MACH.isLibraryPresent=function(sLibrary){};
/**
 * This function checks whether there exists a section with a specific name. Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name.
 * @returns {Bool} 
 */
MACH.isSectionNamePresent=function(sSectionName){};