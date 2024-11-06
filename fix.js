// fix.js, 07/11/2024

const fs = require('fs');
const path = require('path');

/**
 * 🙏 Dear Code Deities,
 * Please bless this code with stability and bug-free execution.
 * May the recursive directory reading be swift and accurate.
 * Let the file processing be smooth and efficient.
 * Grant us the power to detect and fix issues with ease.
 * And may the final result be flawless and reliable.
 * Amen. 🙏
 */

function readDirRecursive(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const
            fullPath = path.join(dir, file),
            stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            readDirRecursive(fullPath);
        } else if (path.extname(fullPath) === '.sg') {
            processFile(fullPath);
        }
    }
}

function processFile(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');

    content = content.replace(/\$/g, '\\$');

    const
        detectRegex = /(function\s+detect\s*\([\s\S]*?\{)([\s\S]*?)(\n\})/,
        match = content.match(detectRegex);

    if (match) {
        const [
            fullMatch,
            detectStart,
            detectBody,
            detectEnd
        ] = match;

        if (!detectBody.includes('return result();')) {
            const
                updatedBody = `${detectBody.trimEnd()}\n\n    return result();`,
                newFunction = `${detectStart}${updatedBody}${detectEnd}`;

            content = content.replace(fullMatch, newFunction);
            content = content.replaceAll('\\$', '$');

            fs.writeFileSync(filePath, content, 'utf8');
            console.log(`Обработан файл: ${filePath}`);
        }
    }
}

readDirRecursive('db');