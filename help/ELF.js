/**
 * @class
 * @classdesc This is a description of the ELF class.
 */
function ELF(){};
/**
 * @see {@link Binary.compare}
 */
ELF.compare=function(sSignature,nOffset){};
ELF.compareEP=function(sSignature,nOffset){};
/**
 * @see {@link Binary.findByte}
 */
ELF.findByte=function(nOffset,nSize,cValue){};
/**
 * @see {@link Binary.findDword}
 */
ELF.findDword=function(nOffset,nSize,nValue){};
/**
 * @see {@link Binary.findSignature}
 */
ELF.findSignature=function(nOffset,nSize,Signature){};
/**
 * @see {@link Binary.findString}
 */
ELF.findString=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.findWord}
 */
ELF.findWord=function(nOffset,nSize,sValue){};
ELF.getElfHeader_ehsize=function(){};
ELF.getElfHeader_entry=function(){};
ELF.getElfHeader_entry64=function(){};
ELF.getElfHeader_flags=function(){};
ELF.getElfHeader_machine=function(){};
ELF.getElfHeader_phentsize=function(){};
ELF.getElfHeader_phnum=function(){};
ELF.getElfHeader_phoff=function(){};
ELF.getElfHeader_phoff64=function(){};
ELF.getElfHeader_shentsize=function(){};
ELF.getElfHeader_shnum=function(){};
ELF.getElfHeader_shoff=function(){};
ELF.getElfHeader_shoff64=function(){};
ELF.getElfHeader_shstrndx=function(){};
ELF.getElfHeader_type=function(){};
ELF.getElfHeader_version=function(){};
/**
 * @see {@link Binary.getFileDirectory}
 */
ELF.getFileDirectory=function(){};
ELF.getGeneralOptions=function(){};
/**
 * @see {@link Binary.getSize}
 */
ELF.getSize=function(){};
ELF.isSectionNamePresent=function(sSectionName){};
/**
 * @see {@link Binary.}
 */
ELF.isSignaturePresent=function(nOffset,nSize,sSignature){};
ELF.isStringInTablePresent=function(sSectionName,sString){};
/**
 * @see {@link Binary.}
 */
ELF.readByte=function(nOffset){};
/**
 * @see {@link Binary.}
 */
ELF.readDword=function(nOffset){};
/**
 * @see {@link Binary.}
 */
ELF.readWord=function(nOffset){};
/**
 * @see {@link Binary.}
 */
ELF.getString=function(nOffset,nSize){};