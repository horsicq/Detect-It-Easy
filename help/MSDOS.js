/**
 * @class
 * @classdesc This is a description of the MSDOS class.
 */
function MSDOS(){}
/**
 * @see Binary.calculateEntropy
 */
MSDOS.calculateEntropy=function(nOffset,nSize){}
/**
 * @see Binary.calculateMD5
 */
MSDOS.calculateMD5=function(nOffset,nSize){}
/**
 * @see Binary.compare
 */
MSDOS.compare=function(sSignature,nOffset){}
/**
  * @see PE.compareEP
 */
MSDOS.compareEP=function(sSignature,nOffset){}
/**
 * @see Binary.findByte
 */
MSDOS.findByte=function(nOffset,nSize,cValue){}
/**
 * @see Binary.findDword
 */
MSDOS.findDword=function(nOffset,nSize,nValue){}
/**
 * @see Binary.findSignature
 */
MSDOS.findSignature=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.findString
 */
MSDOS.findString=function(nOffset,nSize,sValue){}
/**
 * @see Binary.findWord
 */
MSDOS.findWord=function(nOffset,nSize,sValue){}
/**
 * @see Binary.getSignature
 */
MSDOS.getSignature=function(nOffset,nSize){}
/**
 * @see Binary.getSize
 */
MSDOS.getSize=function(){}
/**
 * @see Binary.isSignaturePresent
 */
MSDOS.isSignaturePresent=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.readByte
 */
MSDOS.readByte=function(nOffset){}
/**
 * @see Binary.readDword
 */
MSDOS.readDword=function(nOffset){}
/**
 * @see Binary.readQword
 */
ELF.readQword=function(nOffset){}
/**
 * @see Binary.readWord
 */
MSDOS.readWord=function(nOffset){}
/**
 * @see Binary.swapBytes
 */
MSDOS.swapBytes=function(nValue){}
/**
 * @see Binary.getString
 */
MSDOS.getString=function(nOffset,nSize){}
/**
 * @see Binary.getFileDirectory
 */
MSDOS.getFileDirectory=function(){}
/**
 * Get the file offset of the overlay.
 * @returns {Int}
 */
MSDOS.getOverlayOffset=function(){}
/**
 * Get the size of the overlay.
 * @returns {Int}
 */
MSDOS.getOverlaySize=function(){}
/**
 * Check if an overlay is present.
 * @returns {Bool}
 */
MSDOS.isOverlayPresent=function(){}
/**
 * Check if the file is a <b>N</b>ew <b>E</b>xecutable.
 * @returns {Bool}
 */
MSDOS.isNE=function(){}
/**
 * Check if the file is a <b>L</b>inear <b>E</b>xecutable.
 * @returns {Bool}
 */
MSDOS.isLE=function(){}
/**
 * Check if the file is a <b>L</b>inear e<b>X</b>ecutable.
 * @returns {Bool}
 */
MSDOS.isLX=function(){}
/**
 * @see PE.compareOverlay
 */
MSDOS.compareOverlay=function(sSignature,nOffset){}
/**
 * Get the offset of the entry point.
 * @returns {Int} If an error occurs, -1 will be returned.
 */
MSDOS.getEntryPointOffset=function(){}
/**
 * @see Binary.getFileBaseName
 */
MSDOS.getFileBaseName=function(){}
/**
 * @see Binary.getFileSuffix
 */
MSDOS.getFileSuffix=function(){}
/**
 * @see Binary.getFileCompleteSuffix
 */
MSDOS.getFileCompleteSuffix=function(){}