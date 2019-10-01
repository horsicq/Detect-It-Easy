/**
 * @class
 * @classdesc This is a description of the ELF class.
 */
function ELF(){}
/**
 * @see Binary.calculateEntropy
 */
ELF.calculateEntropy=function(nOffset,nSize){}
/**
 * @see Binary.calculateMD5
 */
ELF.calculateMD5=function(nOffset,nSize){}
/**
 * @see Binary.compare
 */
ELF.compare=function(sSignature,nOffset){}
/**
 * @see PE.compareEP
 */
ELF.compareEP=function(sSignature,nOffset){}
/**
 * @see Binary.findByte
 */
ELF.findByte=function(nOffset,nSize,cValue){}
/**
 * @see Binary.findDword
 */
ELF.findDword=function(nOffset,nSize,nValue){}
/**
 * @see Binary.findSignature
 */
ELF.findSignature=function(nOffset,nSize,sSignature){}
/**
 * @see Binary.findString
 */
ELF.findString=function(nOffset,nSize,sValue){}
/**
 * @see Binary.findWord
 */
ELF.findWord=function(nOffset,nSize,sValue){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_ehsize=function(){}
/**
 * @returns {UInt}
 */
ELF.getElfHeader_entry=function(){}
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_entry64=function(){}
/**
 * @returns {UInt}
 */
ELF.getElfHeader_flags=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_machine=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_phentsize=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_phnum=function(){}
/**
 * @returns {UInt}
 */
ELF.getElfHeader_phoff=function(){}
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_phoff64=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shentsize=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shnum=function(){}
/**
 * @returns {UInt}
 */
ELF.getElfHeader_shoff=function(){}
/**
 * @returns {UInt64}
 */
ELF.getElfHeader_shoff64=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_shstrndx=function(){}
/**
 * @returns {UShort}
 */
ELF.getElfHeader_type=function(){}
/**
 * @returns {UInt}
 */
ELF.getElfHeader_version=function(){}
/**
 * @see Binary.getFileDirectory
 */
ELF.getFileDirectory=function(){}
/**
 * @see Binary.getFileBaseName
 */
ELF.getFileBaseName=function(){}
/**
 * @see Binary.getFileSuffix
 */
ELF.getFileSuffix=function(){}
/**
 * @see Binary.getFileCompleteSuffix
 */
ELF.getFileCompleteSuffix=function(){}
/**
 * Get a string in the form of <code>"<i>ELFtype</i> <i>ELFmode</i>"</code>. For example <code>"executable x86"</code> or <code>"shared object amd64"</code>.
 * @returns {String}
 */
ELF.getGeneralOptions=function(){}
/**
 * @see Binary.getSignature
 */
ELF.getSignature=function(nOffset,nSize){}
/**
 * @see Binary.getSize
 */
ELF.getSize=function(){}
/**
 * Check if a section exists with a specific name or matches a regular expression.
 * @param {String} sSectionName - Section name or pattern.
 * @returns {Bool}
 */
ELF.isSectionNamePresent=function(sSectionName){}
/**
 * @see Binary.isSignaturePresent
 */
ELF.isSignaturePresent=function(nOffset,nSize,sSignature){}
/**
 * Check if a string exists in the table.
 * @param {String} sSectionName - Section name.
 * @param {String} sString - String.
 * @returns {Bool}
 */
ELF.isStringInTablePresent=function(sSectionName,sString){}
/**
 * @see Binary.readByte
 */
ELF.readByte=function(nOffset){}
/**
 * @see Binary.readDword
 */
ELF.readDword=function(nOffset){}
/**
 * @see Binary.readQword
 */
ELF.readQword=function(nOffset){}
/**
 * @see Binary.readWord
 */
ELF.readWord=function(nOffset){}
/**
 * @see Binary.swapBytes
 */
ELF.swapBytes=function(nValue){}
/**
 * @see Binary.getString
 */
ELF.getString=function(nOffset,nSize){}
/**
 * Get the file offset of a section.
 * @param {Int} nSection - Section number.
 * @returns {UInt}
 */
ELF.getSectionFileOffset=function(nSection){}
/**
 * Get the file size of a section.
 * @param {Int} nSection - Section number.
 * @returns {UInt}
 */
ELF.getSectionFileSize=function(nSection){}
/**
 * Get the number of a section with a specific name.
 * @param {String} sSectionName - Section name.
 * @returns {Int} 0-based section number, or <code>-1</code> if there is no section with that name.
 */
ELF.getSectionNumber=function(sSectionName){}
/**
 * Convert a relative virtual address (RVA) to a file offset.
 * @param {UInt64} nRVA
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
ELF.RVAToOffset=function(nRVA){}
/**
 * Convert a virtual address (VA) to a file offset.
 * @param {UInt64} nVA
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
ELF.VAToOffset=function(nVA){}
/**
 * Convert a file offset to a relative virtual address (RVA).
 * @param {UInt64} nOffset
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
ELF.OffsetToRVA=function(nOffset){}
/**
 * Convert a file offset to a virtual address (VA).
 * @param {UInt64} nOffset
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
ELF.OffsetToVA=function(nOffset){}
/**
 * Get the number of sections.
 * @returns {Int}
 */
MACH.getNumberOfSections=function(){}
/**
 * Get the number of programs in the program header table(pht).
 * @returns {Int}
 */
MACH.getNumberOfPrograms=function(){}
/**
 * Get the file offset of a program.
 * @param {Int} nProgram - Program number.
 * @returns {UInt}
 */
ELF.getProgramFileOffset=function(nProgram){}
/**
 * Get the file size of a program.
 * @param {Int} nProgram - Program number.
 * @returns {UInt}
 */
ELF.getProgramFileSize=function(nProgram){}
/**
 * Get the size of the overlay.
 * @returns {Int}
 */
ELF.getOverlaySize=function(){}
/**
 * Get the file offset of the overlay.
 * @returns {Int}
 */
ELF.getOverlayOffset=function(){}
/**
 * Check if an overlay is present.
 * @returns {Bool}
 */
ELF.isOverlayPresent=function(){}
/**
 * @see PE.compareOverlay
 */
ELF.compareOverlay=function(sSignature,nOffset){}
/**
 * Get the offset of the entry point.
 * @returns {Int64} If an error occurs, -1 will be returned.
 */
ELF.getEntryPointOffset=function(){}