/**
 * @class
 * @classdesc This is a description of the MACH class.
 */
function MACH(){}
/**
 * @see Binary.calculateEntropy
 */
MACH.calculateEntropy=function(nOffset,nSize){}
/**
 * @see Binary.calculateMD5
 */
MACH.calculateMD5=function(nOffset,nSize){}
/**
 * @see Binary.compare
 */
MACH.compare=function(sSignature,nOffset){}
/**
 * @see PE.compareEP
 */
MACH.compareEP=function(sSignature,nOffset){}
/**
 * @see Binary.findByte
 */
MACH.findByte=function(nOffset,nSize,cValue){}
/**
 * @see Binary.findDword
 */
MACH.findDword=function(nOffset,nSize,nValue){}
/**
 * @see Binary.findSignature
 */
MACH.findSignature=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.findString
 */
MACH.findString=function(nOffset,nSize,sValue){}
/**
 * @see Binary.findWord
 */
MACH.findWord=function(nOffset,nSize,sValue){}
/**
 * @see Binary.getSignature
 */
MACH.getSignature=function(nOffset,nSize){}
/**
 * @see Binary.getSize
 */
MACH.getSize=function(){}
/**
 * @see Binary.isSignaturePresent
 */
MACH.isSignaturePresent=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.readByte
 */
MACH.readByte=function(nOffset){}
/**
 * @see Binary.readDword
 */
MACH.readDword=function(nOffset){}
/**
 * @see Binary.readWord
 */
MACH.readWord=function(nOffset){}
/**
 * @see Binary.swapBytes
 */
MACH.swapBytes=function(nValue){}
/**
 * @see Binary.getString
 */
MACH.getString=function(nOffset,nSize){}
/**
 * @see Binary.getFileDirectory
 */
MACH.getFileDirectory=function(){}
/**
 * Get a string in the form of <code>"<i>MACHtype</i><i>MACHmode</i>"</code>. For example <code>"EXE32"</code> or <code>"DYLIB64"</code>.
 * @returns {String}
 */
MACH.getGeneralOptions=function(){}
/**
 * Get the current version of a library.
 * @param {String} sLibrary - The name of the library.
 * @returns {String}
 */
MACH.getLibraryCurrentVersion=function(sLibrary){}
/**
 * Get the number of sections.
 * @returns {Int}
 */
MACH.getNumberOfSections=function(){}
/**
 * Check if there is a library with a specific name in the import table.
 * @param {String} sLibraryName - The name of the library.
 * @returns {Bool}
 */
MACH.isLibraryPresent=function(sLibrary){}
/**
 * Check if a section exists with a specific name or matches a regular expression.
 * @param {String} sSectionName - Section name or pattern.
 * @returns {Bool}
 */
MACH.isSectionNamePresent=function(sSectionName){}
/**
 * Get the number of a section with a specific name.
 * @param {String} sSectionName - Section name.
 * @returns {Int} 0-based section number, or <code>-1</code> if there is no section with that name.
 */
MACH.getSectionNumber=function(sSectionName){}