/**
 * @class
 * @classdesc This is a description of the Binary class.
 */
function Binary(){};
/**
 * The function calculates entropy.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @returns {Float} Result in the form of quantity of bits per byte. Since there is 8 bits in a byte, the maximum entropy will be 8.0.
 */
Binary.calculateEntropy=function(nOffset,nSize){};
/**
 * The function calculates MD5 hash
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @returns {String} MD5 hash
 */
Binary.calculateMD5=function(nOffset,nSize){};
/**
 * The function compares bytes with a string signature.
 * <p>The signature may contain both lowercase and uppercase characters.
 * Gaps are skipped while processing lines, and “.” and “?” represent any character.
 * <p>Can use ANSI symbols too. For example "01'Test'01".
 * <p>In the PE class can use # and $:
 * <p># for absolute jump
 * <p>$ for relative jump

 * @param {String} sString - The signature.
 * @param {UInt} nOffset - The offset in the file. By default is 0.
 * @returns {Bool} 
 * @example
    if(Binary.compare("'7z'BCAF271C")) // Compare file header(nOffset=0)
    {
        sVersion=Binary.readByte(6)+"."+Binary.readByte(7);
        bDetected=1;
    }
 * @example
    if(Binary.compare("'WAVEfmt '",8)) // Compare file from offset 8
    {
        bDetected=1;
    }
 */
Binary.compare=function(sString,nOffset){};
/**
 * Search for byte in the file.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {UChar} cValue - The byte value.
 * @returns {Int} The function returns the offset in the file, if the value is found. If nothing is found, -1 is returned.
 */
Binary.findByte=function(nOffset,nSize,cValue){};
/**
 * Search for word in the file.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {UShort} sValue - The word value.
 * @returns {Int} The function returns the offset in the file, if the value is found. If nothing is found, -1 is returned.
 */
Binary.findWord=function(nOffset,nSize,sValue){};
/**
 * Search for dword in the file.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {UInt} nValue - The dword value.
 * @returns {Int} The function returns the offset in the file, if the value is found. If nothing is found, -1 is returned.
 */
Binary.findDword=function(nOffset,nSize,nValue){};
/**
 * Search for string in the file.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {String} sValue - The string value.
 * @returns {Int} The function returns the offset in the file, if the value is found. If nothing is found, -1 is returned.
 */
Binary.findString=function(nOffset,nSize,sValue){};
/**
 * Search for signature in the file.
 * @see {@link Binary.compare}
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {String} sValue - The signature.
 * @returns {Int} The function returns the offset in the file, if the signature is found. If nothing is found, -1 is returned.
 */
Binary.findSignature=function(nOffset,nSize,sValue){};
/**
 * Get file directory
 * @returns {String} 
 */
Binary.getFileDirectory=function(){};
/**
 * The function returns signature as string.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @returns {String} Signature.
 * @example
    var signature=Binary.getSignature(0,4);
    if(signature=="AA5411DD")
    {
        bDetected=1;
    }
*/
Binary.getSignature=function(){};
/**
 * Get file size
 * @returns {UInt} 
 */
Binary.getSize=function(){};
/**
 * Read string from specific offset. A string is read up to the first unreadable character or up to the maximum string.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The maximum size of the string. By default is 50.
 * @returns {String} 
 * @example
    var sString=Binary.getString(0x100,32); // Read a string from offset 0x100, maximum length 32 bytes.
    var sString=Binary.getString(60); // read a string from offset 60, maximum length 50 bytes(default value).
 */
Binary.getString=function(nOffset,nSize){};
/**
 * This function checks whether there exists a signature. 
 * @see {@link Binary.compare}
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - The size of memory.
 * @param {String} sValue - The signature.
 * @returns {Bool}
 */
Binary.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * Read byte value from the file.
 * @param {UInt} nOffset - The offset in the file.
 * @returns {UChar} The byte value.
 */
Binary.readByte=function(nOffset){};
/**
 * Read dword value from the file.
 * @param {UInt} nOffset - The offset in the file.
 * @returns {UInt} The dword value.
 */
Binary.readDword=function(nOffset){};
/**
 * Read word from the file.
 * @param {UInt} nOffset - The offset in the file.
 * @returns {UShort} The word value.
 */
Binary.readWord=function(nOffset){};