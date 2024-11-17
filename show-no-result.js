const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Функция для проверки содержимого файла
function checkFileContent(filePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return reject(err);
            }

            const hasDetectFunction = data.includes('function detect(');
            const hasReturnResult = data.includes('return result(');

            if (hasDetectFunction && !hasReturnResult) {
                resolve(filePath);
            } else {
                resolve(null);
            }
        });
    });
}

// Функция для обхода папок и поиска файлов
async function findFiles(rootDir, extensions, results = []) {
    const files = fs.readdirSync(rootDir);

    for (const file of files) {
        const filePath = path.join(rootDir, file);
        const stat = fs.statSync(filePath);

        if (stat.isDirectory()) {
            await findFiles(filePath, extensions, results);
        } else if (extensions.includes(path.extname(file))) {
            const result = await checkFileContent(filePath);
            if (result) {
                results.push(result);
            }
        }
    }

    return results;
}

// Основная функция для поиска файлов в указанных папках
async function main() {
    const directories = ['db', 'db_extra', 'db_custom'];
    const extensions = ['.sg'];
    let results = [];

    for (const dir of directories) {
        if (fs.existsSync(dir)) {
            const dirResults = await findFiles(dir, extensions);
            results = results.concat(dirResults);
        }
    }

    console.log('Files matching criteria:');
    results.forEach(file => {
        console.log(file);
        exec(`code ${file}`, (err) => {
            if (err) {
                console.error(`Error opening file ${file}:`, err);
            }
        });
    });
}

main().catch(err => console.error(err));