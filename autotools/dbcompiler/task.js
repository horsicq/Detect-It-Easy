const fs = require("fs");
const path = require("path");
const UglifyJS = require("uglify-js");

const inputDirs = ["db", "db_custom", "db_extra"];
const outputDir = "dbs_min";

var stats = {
    total: 0,
    minified: 0,
    copied: 0,
    failed: 0,
};

const failedFiles = [];
const copiedFiles = [];

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

function processFile(srcFile, dstFile) {
    stats.total++;

    let text;
    try {
        text = fs.readFileSync(srcFile, "utf8");
    } catch (err) {
        stats.failed++;
        failedFiles.push({ file: srcFile, reason: "Read error: " + err.message });
        console.warn("[ERROR/READ] " + srcFile + " — " + err.message);
        return;
    }

    if (shouldMinify(srcFile)) {
        try {
            // Pre-process to fix strict mode issues
            text = fixDeleteStatements(text);

            const result = UglifyJS.minify(text, {
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

            if (result.error) throw result.error;

            var legacyCompatibleCode =
                replaceArrowFunctions( // replace arrow functions with regular functions
                    replaceLetWithVarSafe( // replace `let` with `var` to ensure compatibility with older engines
                        result.code.trim()
                    )
                );

            fs.mkdirSync(path.dirname(dstFile), { recursive: true });
            fs.writeFileSync(dstFile, legacyCompatibleCode, "utf8");
            stats.minified++;
            console.log("[MINIFIED] " + srcFile);
        } catch (e) {
            fs.mkdirSync(path.dirname(dstFile), { recursive: true });
            fs.writeFileSync(dstFile, text, "utf8");
            stats.failed++;
            failedFiles.push({ file: srcFile, reason: e.message });
            console.warn("[FAILED] " + srcFile + " — " + e.message);
        }
    } else {
        fs.mkdirSync(path.dirname(dstFile), { recursive: true });
        fs.writeFileSync(dstFile, text, "utf8");
        stats.copied++;
        copiedFiles.push(srcFile);
        console.log("[COPIED] " + srcFile);
    }
}

function walk(srcDir, relBase, dstBase) {
    const items = fs.readdirSync(srcDir);
    for (const item of items) {
        const srcPath = path.join(srcDir, item);

        const stat = fs.statSync(srcPath);
        if (stat.isDirectory()) {
            walk(srcPath, relBase, dstBase);
        } else {
            processFile(srcPath, path.join(dstBase, path.relative(relBase, srcPath)));
        }
    }
}

(async () => {
    for (const dir of inputDirs) {
        if (fs.existsSync(dir)) {
            const dstSubdir = path.join(outputDir, path.basename(dir));
            walk(dir, dir, dstSubdir);
        } else {
            console.warn("[SKIP] Dir not found: " + dir);
        }
    }

    let report = "\n[V] Done!\n" +
        `— Total:     ${stats.total}\n` +
        `— Minified:  ${stats.minified}\n` +
        `— Copied:    ${stats.copied}\n` +
        `— Failed:    ${stats.failed}\n`;

    if (copiedFiles.length > 0) {
        report += "\n[I] Copied (unsupported extension):\n" + copiedFiles.map((f) => " • " + f).join("\n") + "\n";
    }

    if (failedFiles.length > 0) {
        report += "\n[X] Failed to minify:\n" + failedFiles.map((f) => ` • ${f.file} — ${f.reason}`).join("\n") + "\n";
    }

    console.log(report);
})();
