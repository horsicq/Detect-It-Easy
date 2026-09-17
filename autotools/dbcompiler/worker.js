const { parentPort, workerData } = require("worker_threads");
const fs = require("fs");
const path = require("path");
const UglifyJS = require("uglify-js");

const TRANSIENT_FILE_SYSTEM_ERRORS = new Set([
    "EACCES",
    "EBUSY",
    "EMFILE",
    "ENFILE",
    "EPERM",
    "UNKNOWN"
]);

function runFileSystemOperation(operation) {
    const retryDelays = [10, 25, 50, 100, 200];

    for (let attempt = 0; ; attempt++) {
        try {
            return operation();
        } catch (e) {
            if (!TRANSIENT_FILE_SYSTEM_ERRORS.has(e.code) || attempt === retryDelays.length) {
                throw e;
            }

            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, retryDelays[attempt]);
        }
    }
}

function writeIfChanged(filePath, newContent) {
    newContent = newContent.replace(/[\r\n]+$/, "");

    if (fs.existsSync(filePath)) {
        try {
            const existingContent = fs.readFileSync(filePath, "utf8");
            if (existingContent === newContent) {
                return false;
            }
        } catch (e) { }
    }
    runFileSystemOperation(() => fs.writeFileSync(filePath, newContent, "utf8"));
    return true;
}

function createDirectory(directoryPath) {
    runFileSystemOperation(() => fs.mkdirSync(directoryPath, { recursive: true }));
}

function shouldMinify(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ext === ".sg" || ext === "";
}

function isJson(filePath) {
    return path.extname(filePath).toLowerCase() === ".json";
}

/**
 * Universal safe JavaScript parser
 * Skips strings, regular expressions and comments
 * @param {string} text - input JS code
 * @param {function} replacer - Callback: (codeFragment, position, fullText) => {replacement, offset} | null
 * @returns {string} - processed code
 */
function parseJSCodeSafe(text, replacer) {
    let result = '';
    let i = 0;

    while (i < text.length) {
        const char = text[i];

        // Comments
        if (char === '/') {
            // Single-line comment: //
            if (i + 1 < text.length && text[i + 1] === '/') {
                result += '//';
                i += 2;
                while (i < text.length && text[i] !== '\n' && text[i] !== '\r') {
                    result += text[i++];
                }
                // Include newline characters
                while (i < text.length && (text[i] === '\r' || text[i] === '\n')) {
                    result += text[i++];
                }
                continue;
            }

            // Multi-line comment: /* */
            if (i + 1 < text.length && text[i + 1] === '*') {
                result += '/*';
                i += 2;
                while (i < text.length) {
                    if (text[i] === '*' && i + 1 < text.length && text[i + 1] === '/') {
                        result += '*/';
                        i += 2;
                        break;
                    }
                    result += text[i++];
                }
                continue;
            }
        }

        // Strings
        if (char === '"' || char === "'" || char === '`') {
            const quote = char;
            result += char;
            i++;

            while (i < text.length) {
                const c = text[i];
                result += c;
                i++;

                if (c === '\\' && i < text.length) {
                    // Escaped character
                    result += text[i++];
                } else if (c === quote) {
                    // Closing quote
                    break;
                }
            }
            continue;
        }

        // Regular expressions
        if (char === '/') {
            // Heuristic: check context before '/'
            const before = text.substring(Math.max(0, i - 30), i).trim();
            const isLikelyRegex = /[\(=,;:!&|?{}\[\]]\s*$/.test(before) ||
                /^(return|throw|=>)\s*$/.test(before) ||
                before === '';

            if (isLikelyRegex) {
                result += char;
                i++;

                while (i < text.length) {
                    const c = text[i];
                    result += c;
                    i++;

                    if (c === '\\' && i < text.length) {
                        // Escaped character in regex
                        result += text[i++];
                    } else if (c === '/') {
                        // Closing '/', read flags
                        while (i < text.length && /[gimsuvy]/.test(text[i])) {
                            result += text[i++];
                        }
                        break;
                    }
                }
                continue;
            }
        }

        // Regular code
        const remaining = text.substring(i);
        const replaceResult = replacer(remaining, i, text);

        if (replaceResult && replaceResult.replacement !== null && replaceResult.offset > 0) {
            result += replaceResult.replacement;
            i += replaceResult.offset;
        } else {
            result += char;
            i++;
        }
    }

    return result;
}

/**
 * Replace `let` with `var`
 */
function replaceLetWithVarSafe(text) {
    return parseJSCodeSafe(text, (fragment) => {
        // Check if fragment starts with a valid identifier character
        if (!/^[a-zA-Z_$]/.test(fragment)) {
            return null;
        }

        // Read complete identifier
        let word = '';
        let offset = 0;
        while (offset < fragment.length && /[a-zA-Z0-9_$]/.test(fragment[offset])) {
            word += fragment[offset++];
        }
        // Replace only 'let'; return other identifiers unchanged
        if (word === 'let') {
            return { replacement: 'var', offset };
        } else {
            return { replacement: word, offset };
        }
    });
}

/**
 * Replace arrow functions with traditional functions
 * Direct regex replacement after minification
 */
function replaceArrowFunctions(text) {
    // Simple direct replacement without complex parsing
    // UglifyJS output doesn't have regex/string issues with arrow functions

    // 1. ()=>{...} -> function(){...}
    text = text.replace(/\(\)\s*=>\s*\{/g, 'function(){');

    // 2. (args)=>{...} -> function(args){...}
    // Match balanced parentheses
    text = text.replace(/\(([^()]*)\)\s*=>\s*\{/g, 'function($1){');

    // 3. Single arg with block: arg=>{...} -> function(arg){...}
    text = text.replace(/\b([a-zA-Z_$][\w$]*)\s*=>\s*\{/g, 'function($1){');

    // 4. Concise forms (no braces) - need to find expression end
    // ()=>expr -> function(){return expr}
    // This is complex, skip for now as UglifyJS typically uses braces

    return text;
}

function fixDeleteStatements(text) {
    return parseJSCodeSafe(text, (fragment) => {
        const match = fragment.match(/^delete\s+([a-zA-Z_$][\w$]*)(\s*;?)/);

        if (!match) {
            return null;
        }

        const varName = match[1];
        const trailing = match[2];

        // Check that this is not delete obj.prop or delete arr[0]
        const afterMatch = fragment.substring(match[0].length);
        if (afterMatch.length > 0 && /^[.\[]/.test(afterMatch)) {
            // This is a property delete, leave unchanged
            return {
                replacement: match[0],
                offset: match[0].length
            };
        }

        // Replace delete varName with varName=undefined
        return {
            replacement: varName + '=undefined' + trailing,
            offset: match[0].length
        };
    });
}

/**
 * Safely replaces the value of bDetected variable by toggling its boolean state.
 * 
 * @param {string} text - The JavaScript code text to parse and process
 * @returns {string} The text with bDetected values toggled (0 becomes 1, 1 becomes 0)
 * 
 * @description
 * Parses the provided text using parseJSCodeSafe and searches for patterns matching
 * "bDetected = !0" or "bDetected = !1". When found, toggles the numeric value and
 * returns the modified text with the replacement applied.
 * 
 * @example
 * replaceBDetectedSafe('bDetected = !0'); // Returns: 'bDetected=1'
 * replaceBDetectedSafe('bDetected = !1'); // Returns: 'bDetected=0'
 */
function replaceBDetectedSafe(text) {
    return parseJSCodeSafe(text, (fragment) => {
        const match = fragment.match(/^bDetected\s*=\s*!\s*([01])/);

        if (match) {
            const newValue = match[1] === '0' ? '1' : '0';
            return {
                replacement: 'bDetected=' + newValue,
                offset: match[0].length
            };
        }

        return null;
    });
}

/**
 * Replaces common constructor calls with their simplified equivalents in JavaScript code.
 * 
 * Safely transforms:
 * - `String()` → `""`
 * - `Boolean()` → `!1`
 * - `Number()` → `0`
 * 
 * Only replaces constructors that are not preceded by a dot (.) or identifier character,
 * ensuring that property accesses and method calls are not affected.
 * 
 * @param {string} text - The JavaScript code text to process
 * @returns {string} The text with constructor calls replaced by their simplified forms
 */
function replaceConstructorsSafe(text) {
    return parseJSCodeSafe(text, (fragment, index, fullText) => {
        // Check context: there should be no dot or identifier character before
        const charBefore = index > 0 ? fullText[index - 1] : '';
        if (charBefore === '.' || /[a-zA-Z0-9_$]/.test(charBefore)) {
            return null;
        }

        let match;

        // String() -> ""
        match = fragment.match(/^String\s*\(\s*\)/);
        if (match) {
            return {
                replacement: '""',
                offset: match[0].length
            };
        }

        // Boolean() -> !1
        match = fragment.match(/^Boolean\s*\(\s*\)/);
        if (match) {
            return {
                replacement: '!1',
                offset: match[0].length
            };
        }

        // Number() -> 0
        match = fragment.match(/^Number\s*\(\s*\)/);
        if (match) {
            return {
                replacement: '0',
                offset: match[0].length
            };
        }

        return null;
    });
}

const fileApiMethodAliases = {
    getSize: "Sz",
    findSignature: "fSig",
    findString: "fStr",
    compare: "c",
    readBytes: "BA",
    read_uint8: "U8",
    read_int8: "I8",
    read_uint16: "U16",
    read_int16: "I16",
    read_float16: "F16",
    read_uint24: "U24",
    read_int24: "I24",
    read_uint32: "U32",
    read_int32: "I32",
    read_float32: "F32",
    read_uint64: "U64",
    read_int64: "I64",
    read_float64: "F64",
    read_ansiString: "SA",
    read_codePageString: "SC",
    read_ucsdString: "UCSD",
    read_utf8String: "SU8",
    read_unicodeString: "SU16"
};

/**
 * Get the global file-format API name from a database file path.
 * @param {string} filePath - Source database file path.
 * @returns {string|null}
 */
function getFileApiName(filePath) {
    if (path.basename(filePath) === "_init") {
        return null;
    }

    const relativePath = path.relative(process.cwd(), filePath),
        pathParts = relativePath.split(path.sep),
        databaseRoot = pathParts[0],
        formatName = pathParts[1];

    if ((databaseRoot !== "db" && databaseRoot !== "db_custom" && databaseRoot !== "db_extra") ||
        !formatName) {
        return null;
    }

    const initFilePath = path.join(process.cwd(), "db", formatName, "_init");

    if (!fs.existsSync(initFilePath)) {
        return null;
    }

    const initText = fs.readFileSync(initFilePath, "utf8"),
        aliasMatch = initText.match(/\bvar\s+X\s*=\s*([a-zA-Z_$][\w$]*)\s*;/);

    return aliasMatch ? aliasMatch[1] : null;
}

/**
 * Replace the verbose format API name with the X alias initialized by the format `_init`.
 * Base-file methods use the short aliases exposed through the same X object.
 * @param {string} text - Minified JavaScript code.
 * @param {string} filePath - Source database file path.
 * @returns {string}
 */
function replaceFileApiCallsSafe(text, filePath) {
    const fileApiName = getFileApiName(filePath);

    if (!fileApiName) {
        return text;
    }

    let ast = UglifyJS.parse(text, {
        bare_returns: true
    });

    if (path.basename(filePath) === "_init") {
        return text;
    }

    ast.figure_out_scope();

    ast = ast.transform(new UglifyJS.TreeTransformer(function (node) {
        if (node instanceof UglifyJS.AST_Dot &&
            node.expression instanceof UglifyJS.AST_SymbolRef &&
            node.expression.definition().undeclared) {
            const objectName = node.expression.name;

            if (objectName === fileApiName || objectName === "File" || objectName === "X") {
                const parent = this.parent(),
                    alias = fileApiMethodAliases[node.property];

                if (alias && parent instanceof UglifyJS.AST_Call && parent.expression === node) {
                    node.property = alias;
                    node.expression = new UglifyJS.AST_SymbolRef({
                        name: "X",
                        start: node.expression.start,
                        end: node.expression.end
                    });

                    return node;
                }

                if (objectName === fileApiName) {
                    node.expression = new UglifyJS.AST_SymbolRef({
                        name: "X",
                        start: node.expression.start,
                        end: node.expression.end
                    });
                }

                return node;
            }
        }

    }));

    return ast.print_to_string({
        beautify: false,
        comments: false,
        semicolons: false
    });
}

// Main
const { srcFile, dstFile } = workerData;

let result = {
    success: false,
    srcFile: srcFile,
    type: 'unknown',
    error: null
};

try {
    const text = fs.readFileSync(srcFile, "utf8");

    if (shouldMinify(srcFile)) {
        try {
            // Step 1: fix delete statements BEFORE minification
            const fixedText = fixDeleteStatements(text);

            // Step 2: Minification
            const uglifyResult = UglifyJS.minify(fixedText, {
                compress: true,
                mangle: {
                    reserved: ["X"]
                },
                parse: {
                    bare_returns: true,
                },
                output: {
                    beautify: false,
                    comments: false,
                    semicolons: false,
                },
            });

            if (uglifyResult.error) throw uglifyResult.error;

            // Step 3: Post-processing for legacy compatibility
            const legacyCompatibleCode = replaceFileApiCallsSafe(
                replaceConstructorsSafe(
                    replaceBDetectedSafe(
                        replaceArrowFunctions(
                            replaceLetWithVarSafe(uglifyResult.code.trim())
                        )
                    )
                ),
                srcFile
            );

            createDirectory(path.dirname(dstFile));
            const wasWritten = writeIfChanged(dstFile, legacyCompatibleCode);

            result.success = true;
            result.type = wasWritten ? 'minified' : 'skipped';
        } catch (e) {
            createDirectory(path.dirname(dstFile));
            const wasWritten = writeIfChanged(dstFile, text);

            result.success = false;
            result.type = wasWritten ? 'failed' : 'failed-skip';
            result.error = e.message;
        }
    } else if (isJson(srcFile)) {
        try {
            const minified = JSON.stringify(JSON.parse(text));
            createDirectory(path.dirname(dstFile));
            const wasWritten = writeIfChanged(dstFile, minified);

            result.success = true;
            result.type = wasWritten ? 'minified' : 'skipped';
        } catch (e) {
            createDirectory(path.dirname(dstFile));
            const wasWritten = writeIfChanged(dstFile, text);

            result.success = false;
            result.type = wasWritten ? 'failed' : 'failed-skip';
            result.error = e.message;
        }
    } else {
        createDirectory(path.dirname(dstFile));
        const wasWritten = writeIfChanged(dstFile, text);

        result.success = true;
        result.type = wasWritten ? 'copied' : 'copied-skip';
    }
} catch (e) {
    result.success = false;
    result.type = 'error';
    result.error = e.message;
}

parentPort.postMessage(result);
