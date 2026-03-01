const fs = require('fs');
const path = require('path');

/**
 * Рекурсивно находит все .sg файлы в директории
 * @param {string} dir - Путь к директории
 * @param {string[]} fileList - Массив найденных файлов
 * @returns {string[]} Массив путей к .sg файлам
 */
function findSgFiles(dir, fileList = []) {
    try {
        const files = fs.readdirSync(dir);

        files.forEach(file => {
            const filePath = path.join(dir, file);

            try {
                const stat = fs.statSync(filePath);

                if (stat.isDirectory()) {
                    // Рекурсивный обход директорий
                    findSgFiles(filePath, fileList);
                } else if (path.extname(file).toLowerCase() === '.sg') {
                    fileList.push(filePath);
                }
            } catch (err) {
                console.error(`Ошибка доступа к файлу ${filePath}:`, err.message);
            }
        });
    } catch (err) {
        console.error(`Ошибка чтения директории ${dir}:`, err.message);
    }

    return fileList;
}

/**
 * Извлекает первый аргумент из вызова функции meta()
 * @param {string} content - Содержимое файла
 * @returns {string|null} Первый аргумент meta() или null
 */
function extractMetaPrefix(content) {
    // Проверяем наличие " DosX"
    // if (!content.includes(' DosX')) {
    //     return null;
    // }

    // if (!content.includes('BJNFNE')) {
    //     return null;
    // }

    // Ищем вызов meta() с помощью регулярного выражения
    // Поддерживает различные варианты форматирования
    const metaRegex = /meta\s*\(\s*["']([^"']*)["']\s*,/;
    const match = content.match(metaRegex);

    if (match && match[1] && match[1].trim() !== '') {
        return match[1].trim();
    }

    return null;
}

/**
 * Переименовывает файл, добавляя префикс
 * @param {string} filePath - Путь к файлу
 * @param {string} prefix - Префикс для добавления
 * @returns {boolean} true если успешно, false если ошибка
 */
function renameFileWithPrefix(filePath, prefix) {
    try {
        const dir = path.dirname(filePath);
        const fileName = path.basename(filePath);

        // Проверяем, не начинается ли уже файл с этого префикса
        //if (fileName.startsWith(`${prefix}_`)) {
        if (fileName.includes(`_`)) { // Если в имени файла уже есть символ "_", пропускаем переименование
            console.log(`⏭️  Пропускаю ${fileName} - префикс уже есть`);
            return false;
        }

        const newFileName = `${prefix.replace(/ /g, '_')}_${fileName}`;
        const newFilePath = path.join(dir, newFileName);

        // Проверяем, не существует ли уже файл с новым именем
        if (fs.existsSync(newFilePath)) {
            console.warn(`⚠️  Файл ${newFileName} уже существует, пропускаю переименование`);
            return false;
        }

        fs.renameSync(filePath, newFilePath);
        console.log(`✅ Переименован: ${fileName} → ${newFileName}`);
        return true;
    } catch (err) {
        console.error(`❌ Ошибка переименования ${filePath}:`, err.message);
        return false;
    }
}

/**
 * Основная функция обработки файлов
 * @param {string} startDir - Начальная директория для поиска
 */
function processFiles(startDir) {
    console.log(`🔍 Поиск .sg файлов в ${startDir}...\n`);

    const sgFiles = findSgFiles(startDir);
    console.log(`📁 Найдено файлов: ${sgFiles.length}\n`);

    if (sgFiles.length === 0) {
        console.log('Нет .sg файлов для обработки.');
        return;
    }

    let processed = 0;
    let renamed = 0;
    let skipped = 0;

    sgFiles.forEach(filePath => {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const prefix = extractMetaPrefix(content);

            if (prefix) {
                processed++;
                console.log(`\n📄 Обработка: ${path.basename(filePath)}`);
                console.log(`   Префикс: "${prefix}"`);

                if (renameFileWithPrefix(filePath, prefix)) {
                    renamed++;
                } else {
                    skipped++;
                }
            }
        } catch (err) {
            console.error(`❌ Ошибка чтения ${filePath}:`, err.message);
        }
    });

    console.log('\n' + '='.repeat(50));
    console.log(`📊 Статистика:`);
    console.log(`   Всего файлов: ${sgFiles.length}`);
    console.log(`   Обработано: ${processed}`);
    console.log(`   Переименовано: ${renamed}`);
    console.log(`   Пропущено: ${skipped}`);
    console.log('='.repeat(50));
}

// Запуск скрипта
const startDirectory = process.argv[2] || '.';

if (!fs.existsSync(startDirectory)) {
    console.error(`❌ Директория ${startDirectory} не существует!`);
    process.exit(1);
}

console.log('🚀 Запуск скрипта переименования .sg файлов\n');
processFiles(startDirectory);
