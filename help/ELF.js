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
/**
 * @returns {UShort}
 */
ELF.getElfHeader_ehsize=function(){};
/**
 * @returns {UInt}
 */
ELF.getElfHeader_entry=function(){};
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_entry64=function(){};
/**
 * @returns {UInt}
 */
ELF.getElfHeader_flags=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_machine=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_phentsize=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_phnum=function(){};
/**
 * @returns {UInt}
 */
ELF.getElfHeader_phoff=function(){};
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_phoff64=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shentsize=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shnum=function(){};
/**
 * @returns {UInt}
 */
ELF.getElfHeader_shoff=function(){};
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_shoff64=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shstrndx=function(){};
/**
 * @returns {UShort}
 */
ELF.getElfHeader_type=function(){};
/**
 * @returns {UInt}
 */
ELF.getElfHeader_version=function(){};
/**
 * @see {@link Binary.getFileDirectory}
 */
ELF.getFileDirectory=function(){};
/**
 * This function returns a string in the form of <ELFtype><ELFmоde> 
 * @returns {String}
 */
ELF.getGeneralOptions=function(){};
/**
 * @see {@link Binary.getSize}
 */
ELF.getSize=function(){};
/**
 * This function checks whether there exists a section with a specific name. Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name.
 * @returns {Bool} 
 */
ELF.isSectionNamePresent=function(sSectionName){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
ELF.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * This function checks whether there exists a string in the table.
 * @param {String} sSectionName - Section name.
 * @param {String} sString - String.
 * @returns {Bool} 
 */
ELF.isStringInTablePresent=function(sSectionName,sString){};
/**
 * @see {@link Binary.readByte}
 */
ELF.readByte=function(nOffset){};
/**
 * @see {@link Binary.readDword}
 */
ELF.readDword=function(nOffset){};
/**
 * @see {@link Binary.readWord}
 */
ELF.readWord=function(nOffset){};
/**
 * @see {@link Binary.getString}
 */
ELF.getString=function(nOffset,nSize){};