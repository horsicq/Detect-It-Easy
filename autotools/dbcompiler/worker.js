const { parentPort, workerData } = require("worker_threads");
const fs = require("fs");
const path = require("path");
const UglifyJS = require("uglify-js");

function shouldMinify(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ext === ".sg" || ext === "";
}

function replaceLetWithVarSafe(text) {
    let result = '';
    let i = 0;

    while (i < text.length) {
        const char = text[i];

        // Handle string literals: ", ', `
        if (char === '"' || char === "'" || char === '`') {
            const quote = char;
            result += char;
            i++;

            // Read until closing quote, respecting escapes
            while (i < text.length) {
                const c = text[i];
                result += c;

                if (c === '\\' && i + 1 < text.length) {
                    // Skip escaped character
                    i++;
                    result += text[i];
                    i++;
                } else if (c === quote) {
                    // Found closing quote
                    i++;
                    break;
                } else {
                    i++;
                }
            }
            continue;
        }

        // Handle regex literals: /...../flags
        if (char === '/') {
            // Check if this looks like a regex (not division)
            const before = text.substring(Math.max(0, i - 30), i).trim();
            const isLikelyRegex = /[\(=,;:!&|?{}\[\]]\s*$/.test(before) ||
                /^(return|throw|=>)\s*$/.test(before) ||
                before === '';

            if (isLikelyRegex) {
                result += char;
                i++;

                // Read until closing /, respecting escapes
                while (i < text.length) {
                    const c = text[i];
                    result += c;

                    if (c === '\\' && i + 1 < text.length) {
                        // Skip escaped character
                        i++;
                        result += text[i];
                        i++;
                    } else if (c === '/') {
                        // Found closing /, now read flags
                        i++;
                        while (i < text.length && /[gimsuvy]/.test(text[i])) {
                            result += text[i];
                            i++;
                        }
                        break;
                    } else {
                        i++;
                    }
                }
                continue;
            }
        }

        // Regular code - safe to replace 'let'
        // Accumulate word
        if (/[a-zA-Z_$]/.test(char)) {
            let word = '';
            let wordStart = i;

            while (i < text.length && /[a-zA-Z0-9_$]/.test(text[i])) {
                word += text[i];
                i++;
            }

            // Replace 'let' with 'var'
            if (word === 'let') {
                result += 'var';
            } else {
                result += word;
            }
        } else {
            result += char;
            i++;
        }
    }

    return result;
}

function replaceArrowFunctions(text) {
    text = text.replace(/(\([^()]*\))\s*=>\s*\{/g, (m, args) => 'function' + args + ' {');
    text = text.replace(/\(\)\s*=>\s*\{/g, 'function(){');
    text = text.replace(/([a-zA-Z_$][\w$]*)\s*=>\s*\{/g, (m, param) => 'function(' + param + '){');
    return text;
}

function fixDeleteStatements(text) {
    // Replace "delete varName" with "varName = undefined" to avoid strict mode errors
    return text.replace(/\bdelete\s+([a-zA-Z_$][\w$]*)\s*;/g, (match, varName) => {
        return varName + '=undefined;';
    });
}

// Process the file
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
            // Pre-process to fix strict mode issues
            const fixedText = fixDeleteStatements(text);

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

            const legacyCompatibleCode = replaceArrowFunctions(
                replaceLetWithVarSafe(uglifyResult.code.trim())
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
