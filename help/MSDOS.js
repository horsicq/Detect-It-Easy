/**
 * @class
 * @classdesc This is a description of the MSDOS class.
 */
function MSDOS(){};
/**
 * @see {@link Binary.compare}
 */
MSDOS.compare=function(sSignature,nOffset){};
/**
 * @see {@link Binary.findByte}
 */
MSDOS.findByte=function(nOffset,nSize,cValue){};
/**
 * @see {@link Binary.findDword}
 */
MSDOS.findDword=function(nOffset,nSize,nValue){};
/**
 * @see {@link Binary.findSignature}
 */
MSDOS.findSignature=function(nOffset,nSize,Signature){};
/**
 * @see {@link Binary.findString}
 */
MSDOS.findString=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.findWord}
 */
MSDOS.findWord=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.getSize}
 */
MSDOS.getSize=function(){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
MSDOS.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * @see {@link Binary.readByte}
 */
MSDOS.readByte=function(nOffset){};
/**
 * @see {@link Binary.readDword}
 */
MSDOS.readDword=function(nOffset){};
/**
 * @see {@link Binary.readWord}
 */
MSDOS.readWord=function(nOffset){};
/**
 * @see {@link Binary.getString}
 */
MSDOS.getString=function(nOffset,nSize){};
/**
 * @see {@link Binary.getFileDirectory}
 */
MSDOS.getFileDirectory=function(){};
MSDOS.getOverlayOffset=function(){};
MSDOS.getOverlaySize=function(){};
MSDOS.isOverlayPresent=function(){};
MSDOS.isNE=function(){};
MSDOS.isLE=function(){};
MSDOS.isLX=function(){};