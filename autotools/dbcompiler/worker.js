const { parentPort, workerData } = require("worker_threads");
const fs = require("fs");
const path = require("path");
const UglifyJS = require("uglify-js");

function shouldMinify(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ext === ".sg" || ext === "";
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

/**
 * Fix delete statements for strict mode
 * Applied BEFORE minification
 */
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
 * Replace bDetected=!0 and bDetected=!1
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
 * Replace empty constructors with literals
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
                mangle: true,
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
            const legacyCompatibleCode = replaceConstructorsSafe(
                replaceBDetectedSafe(
                    replaceArrowFunctions(
                        replaceLetWithVarSafe(uglifyResult.code.trim())
                    )
                )
            );

            fs.mkdirSync(path.dirname(dstFile), { recursive: true });
            fs.writeFileSync(dstFile, legacyCompatibleCode, "utf8");
            result.success = true;
            result.type = 'minified';
        } catch (e) {
            fs.mkdirSync(path.dirname(dstFile), { recursive: true });
            fs.writeFileSync(dstFile, text, "utf8");
            result.success = false;
            result.type = 'failed';
            result.error = e.message;
        }
    } else {
        fs.mkdirSync(path.dirname(dstFile), { recursive: true });
        fs.writeFileSync(dstFile, text, "utf8");
        result.success = true;
        result.type = 'copied';
    }
} catch (e) {
    result.success = false;
    result.type = 'error';
    result.error = e.message;
}

parentPort.postMessage(result);
