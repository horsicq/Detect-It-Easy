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
    return text.replace(/(?<!["'`])\blet\b(?!["'`])/g, "var");
}

function replaceArrowFunctions(text) {
    text = text.replace(/(\([^()]*\))\s*=>\s*\{/g, (m, args) => 'function' + args + ' {');

    text = text.replace(/\(\)\s*=>\s*\{/g, 'function(){');

    text = text.replace(/([a-zA-Z_$][\w$]*)\s*=>\s*\{/g, (m, param) => 'function(' + param + '){');

    return text;
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

            const result = UglifyJS.minify(text, {
                compress: true,
                mangle: true,
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
                        result.code
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
