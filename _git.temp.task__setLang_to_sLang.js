// 01.07.2025

const fs = require('fs');
const path = require('path');

function replaceSetLangCalls(content) {
    const regex = /_setLang\(([^)]+),\s*bDetected\)\s*;?/g;
    return content.replace(regex, (match, firstArg) => {
        return `sLang = ${firstArg.trim()};`;
    });
}

function processDirectory(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
            processDirectory(fullPath);
        } else if (entry.isFile() && fullPath.endsWith('.sg')) {
            const content = fs.readFileSync(fullPath, 'utf8'), newContent = replaceSetLangCalls(content);

            if (newContent !== content) {
                fs.writeFileSync(fullPath, newContent, 'utf8');
                console.log(`Updated: ${fullPath}`);
            }
        }
    }
}

processDirectory(process.cwd());