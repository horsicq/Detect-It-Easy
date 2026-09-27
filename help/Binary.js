/**
 * @class
 * @classdesc This is a description of the Binary class. This class is used when no other class matches.
 */
function Binary() {}
/**
 * Calculate the entropy of a region of the file.
 * @param {UInt} nOffset - The offset in the file.
 * @param {UInt} nSize - Number of bytes.
 * @returns {Float} Result in the form of quantity of bits per byte. Since there are 8 bits in a byte, the maximum entropy will be 8.0.
 */
Binary.calculateEntropy = function(nOffset, nSize) {}
    /**
     * Calculate the MD5 hash of a region of the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes.
     * @returns {String} MD5 hash.
     */
Binary.calculateMD5 = function(nOffset, nSize) {}
    /**
     * Compares bytes with a hexadecimal string signature.
     * <p>The signature may contain both lowercase and uppercase hexadecimal digits.
     * Spaces are skipped, and <code>.</code> and <code>?</code> represent any digit.
     * <p>Text may be matched by using single quotes. For example <samp>"01'Test'01"</samp>.
     * <p>There are two additional symbols:
     * <br><code>#</code> for absolute jump (e.g. <code>"68########55"</code>);
     * <br><code>$</code> for relative jump (e.g. <code>"E8$$$$$$$$55"</code>).
     *
     * @param {String} sSignature - The signature.
     * @param {UInt} [nOffset=0] - The offset in the file.
     * @returns {Bool}
     * @example
     * if(Binary.compare("'7z'BCAF271C")) // compare file header (nOffset=0)
     * {
     *     sVersion=Binary.readByte(6)+"."+Binary.readByte(7);
     *     bDetected=1;
     * }
     * @example
     * if(Binary.compare("'WAVEfmt '",8)) // compare file from offset 8
     * {
     *     bDetected=1;
     * }
     */
Binary.compare = function(sSignature, nOffset) {}
    /**
     * Search for a byte in the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to search.
     * @param {UChar} cValue - The byte value.
     * @returns {Int} Offset in the file if the value is found; <code>-1</code> otherwise.
     */
Binary.findByte = function(nOffset, nSize, cValue) {}
    /**
     * Search for a word in the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to search.
     * @param {UShort} sValue - The word value.
     * @returns {Int} Offset in the file if the value is found; <code>-1</code> otherwise.
     */
Binary.findWord = function(nOffset, nSize, sValue) {}
    /**
     * Search for a dword in the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to search.
     * @param {UInt} nValue - The dword value.
     * @returns {Int} Offset in the file if the value is found; <code>-1</code> otherwise.
     */
Binary.findDword = function(nOffset, nSize, nValue) {}
    /**
     * Search for a string in the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to search.
     * @param {String} sValue - The string value.
     * @returns {Int} Offset in the file if the value is found; <code>-1</code> otherwise.
     */
Binary.findString = function(nOffset, nSize, sValue) {}
    /**
     * Search for a signature (see {@link Binary.compare compare}) in the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to search.
     * @param {String} sValue - The signature.
     * @returns {Int} Offset in the file if the signature is found; <code>-1</code> otherwise.
     */
Binary.findSignature = function(nOffset, nSize, sValue) {}
    /**
     * Search several signatures using the same parser and matching behavior as findSignature.
     * @param {Number} nOffset - Safe integer file offset; uses findSignature range handling.
     * @param {Number} nSize - Safe integer byte count; uses findSignature range handling.
     * @param {String[]} signatures - At most 128 signatures, with a total text budget of 65536.
     * @returns {Number[]|null} First offset for each signature, or -1 if absent. Invalid arguments
     * return null in the C engine and an empty array in the Qt engine.
     * @see Binary.findSignature
     */
Binary.findSignatures = function(nOffset, nSize, signatures) {}
    /**
     * Find the earliest complete exact byte pattern in the strict file range [nOffset, nOffset+nSize).
     * No string encoding or wildcard interpretation is applied.
     * @param {Number} nOffset - Nonnegative safe integer file offset.
     * @param {Number} nSize - Nonnegative safe integer byte count; the complete range must be in the file.
     * @param {Number[][]} patterns - At most 128 nonempty arrays of integer bytes (0..255),
     * with at most 65536 bytes in total. An empty outer array is allowed.
     * @returns {{offset: Number, patternIndex: Number}|null} Lowest file offset and zero-based
     * pattern index; ties use the lower index. Returns null if absent or arguments are invalid.
     */
Binary.findAnyBytes = function(nOffset, nSize, patterns) {}
    /**
     * Return byte-equality candidates without interpreting the matched data.
     * All pairs within a group must match; group bit g is set when every pair in groups[g] matches.
     * @param {Number} nOffset - Nonnegative safe integer file offset.
     * @param {Number} nSize - Nonnegative safe integer byte count, at most 16 MiB; range must be in the file.
     * @param {Number[][][]} groups - At most 32 nonempty groups and 256 pairs in total.
     * Each pair contains two integer byte offsets in the range 0..tailBytes. An empty outer array is allowed.
     * @param {Number} tailBytes - Integer in 0..4294967295. Candidate positions satisfy p < nSize-tailBytes.
     * @returns {Uint32Array|Number[]|null} Flat [relativeOffset, groupMask, ...] pairs in ascending offset order;
     * each position appears once with all matching bits. Invalid arguments return null.
     * A valid request without candidates returns an empty typed array. Legacy QtScript builds
     * return an ordinary array with the same unsigned values.
     */
Binary.findByteRelationCandidates = function(nOffset, nSize, groups, tailBytes) {}

    /**
     * Get the directory of the file.
     * @returns {String}
     */
Binary.getFileDirectory = function() {}
    /**
     * Get the base name of the file.
     * @returns {String}
     */
Binary.getFileBaseName = function() {}
    /**
     * Get the complete suffix of the file.
     * @returns {String}
     */
Binary.getFileCompleteSuffix = function() {}
    /**
     * Get the suffix of the file.
     * @returns {String}
     */
Binary.getFileSuffix = function() {}
    /**
     * Get a signature string from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes.
     * @returns {String} Signature.
     * @example
     * var signature=Binary.getSignature(0,4);
     * if(signature=="AA5411DD")
     * {
     *     bDetected=1;
     * }
     */
Binary.getSignature = function(nOffset, nSize) {}
    /**
     * Get the size of the file.
     * @returns {UInt}
     */
Binary.getSize = function() {}
    /**
     * Get a text string from the file. A string is read up to the first unreadable character or up to the maximum length.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} [nSize=50] - The maximum size of the string, in bytes.
     * @returns {String}
     * @example
     * var sString=Binary.getString(0x100,32); // read a string from offset 0x100, maximum length 32 bytes
     * var sString=Binary.getString(60); // read a string from offset 60, maximum length 50 bytes (default value)
     */
Binary.getString = function(nOffset, nSize) {}
    /**
     * Check if a signature (see {@link Binary.compare compare}) exists in a region of the file.
     * @param {UInt} nOffset - The offset in the file.
     * @param {UInt} nSize - Number of bytes to check.
     * @param {String} sSignature - The signature.
     * @returns {Bool}
     */
Binary.isSignaturePresent = function(nOffset, nSize, sSignature) {}
    /**
     * Read a byte value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UChar} The byte value.
     */
Binary.readByte = function(nOffset) {}
    /**
     * Read a dword value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UInt} The dword value.
     */
Binary.readDword = function(nOffset) {}
    /**
     * Read a qword value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UInt64} The qword value.
     */
Binary.readQword = function(nOffset) {}
    /**
     * Read a word from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UShort} The word value.
     */
Binary.readWord = function(nOffset) {}
    /**
     * Read a signed byte value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UChar} The byte value.
     */
Binary.readSByte = function(nOffset) {}
    /**
     * Read a signed dword value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UInt} The dword value.
     */
Binary.readSDword = function(nOffset) {}
    /**
     * Read a signed qword value from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UInt64} The qword value.
     */
Binary.readSQword = function(nOffset) {}
    /**
     * Read a signed word from the file.
     * @param {UInt} nOffset - The offset in the file.
     * @returns {UShort} The word value.
     */
Binary.readSWord = function(nOffset) {}
    /**
     * Swap the four bytes of a dword. For example <samp>0x11223344</samp> becomes <samp>0x44332211</samp>.
     * @param nValue {UInt} - The value.
     * @returns {Uint} The value with its bytes swapped.
     */
Binary.swapBytes = function(nValue) {}
    /**
     * Decode one instruction and return the same text, length and next address as the existing disassembly APIs.
     * @param {Number} nAddress - Nonnegative safe integer virtual address.
     * @returns {{text: String, length: Number, nextAddress: Number}|null} Decoded instruction;
     * null for an unmapped address or decoding failure. PE x86/x64 lengths must be in 1..15.
     */
Binary.getDisasmInfo = function(nAddress) {}
