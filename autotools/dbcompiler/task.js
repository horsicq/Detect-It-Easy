const fs = require("fs");
const path = require("path");
const { Worker } = require("worker_threads");
const zlib = require('zlib');
const archiver = require('archiver');

const inputDirs = ["db", "db_custom", "db_extra"];
const outputDir = "dbs_min";
const CACHE_FILE = path.join(outputDir, '.compiler_cache');
const COMPILER_CACHE_KEY = '@compiler';
const MAX_PARALLEL = 16;
const PRESERVED_OUTPUT_FILES = [
    path.join(outputDir, 'timestamp.log')
];

const stats = {
    total: 0,
    minified: 0,
    copied: 0,
    failed: 0,
    skipped: 0,
    deleted: 0,
};

const failedFiles = [];
const copiedFiles = [];

// --- Cache helpers (ADLER32 + CRC32 key)
function adler32(str) {
    let a = 1, b = 0;
    for (let i = 0; i < str.length; i++) {
        a = (a + str.charCodeAt(i)) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

function makeCrc32Table() {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c >>> 0;
    }
    return table;
}

const CRC32_TABLE = makeCrc32Table();
function crc32(str) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ code) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

function computeKeyForPath(p) {
    // Use normalized relative path to project root
    const rel = path.normalize(path.relative(process.cwd(), p)).replace(/\\/g, '/');
    // Combine into 64-bit-like hex
    const big = (BigInt(adler32(rel) >>> 0) << 32n) | BigInt(crc32(rel) >>> 0);
    return big.toString(16);
}

function computeCompilerFingerprint() {
    const compilerFiles = [
        path.join(__dirname, 'worker.js'),
        path.join(__dirname, 'package-lock.json')
    ];
    let source = '';

    for (const filePath of compilerFiles) {
        source += fs.readFileSync(filePath, 'utf8');
    }

    return crc32(source).toString(16);
}

function loadCache() {
    const map = new Map();
    try {
        if (!fs.existsSync(CACHE_FILE)) return map;
        // Read as buffer and try to decompress (Brotli). Fallback to plain text.
        let txt = null;
        try {
            const buf = fs.readFileSync(CACHE_FILE);
            const decompressed = zlib.brotliDecompressSync(buf);
            txt = decompressed.toString('utf8');
        } catch (e) {
            // fallback: try read as utf8 plain text
            try { txt = fs.readFileSync(CACHE_FILE, 'utf8'); } catch (e2) { txt = null; }
        }
        if (!txt) return map;
        const parts = txt.split(';');
        for (const p of parts) {
            if (!p) continue;
            const separator = p.indexOf('=');
            if (separator === -1) continue;
            map.set(p.substring(0, separator), p.substring(separator + 1));
        }
    } catch (e) {
        // ignore parsing errors
    }
    return map;
}

function saveCache(map) {
    try {
        fs.mkdirSync(outputDir, { recursive: true });

        // Sort keys for better compression
        const sorted = Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));

        const parts = [];
        for (const [k, v] of sorted) {
            parts.push(`${k}=${v}`);
        }
        const txt = parts.join(';');

        // Brotli with maximum compression quality
        const buf = zlib.brotliCompressSync(Buffer.from(txt, 'utf8'), {
            params: {
                [zlib.constants.BROTLI_PARAM_QUALITY]: zlib.constants.BROTLI_MAX_QUALITY,
                [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT
            }
        });
        fs.writeFileSync(CACHE_FILE, buf);
    } catch (e) {
        console.warn('[CACHE WRITE FAILED] ' + e.message);
    }
}

function processFile(srcFile, dstFile) {
    return new Promise((resolve) => {
        const worker = new Worker(path.join(__dirname, 'worker.js'), {
            workerData: { srcFile, dstFile },
            execArgv: [],
            resourceLimits: {
                maxOldGenerationSizeMb: 2048,
                maxYoungGenerationSizeMb: 512
            }
        });

        let settled = false;
        const once = (fn) => (...args) => { if (!settled) { settled = true; fn(...args); } };

        worker.on('message', once((result) => {
            if (result.type === 'minified') {
                stats.minified++;
                console.log("[MINIFIED] " + result.srcFile);
            } else if (result.type === 'skipped') {
                stats.minified++;
                stats.skipped++;
                console.log("[SKIP] " + result.srcFile);
            } else if (result.type === 'copied') {
                stats.copied++;
                copiedFiles.push(result.srcFile);
                console.log("[COPIED] " + result.srcFile);
            } else if (result.type === 'copied-skip') {
                stats.copied++;
                stats.skipped++;
                console.log("[SKIP] " + result.srcFile);
            } else if (result.type === 'failed') {
                stats.failed++;
                failedFiles.push({ file: result.srcFile, reason: result.error });
                console.warn("[FAILED] " + result.srcFile + " — " + result.error);
            } else if (result.type === 'failed-skip') {
                stats.failed++;
                stats.skipped++;
                failedFiles.push({ file: result.srcFile, reason: result.error });
                console.log("[SKIP/FAIL] " + result.srcFile);
            } else {
                stats.failed++;
                failedFiles.push({ file: result.srcFile, reason: "Read error: " + result.error });
                console.warn("[ERROR/READ] " + result.srcFile + " — " + result.error);
            }

            resolve();
        }));

        worker.on('error', once((err) => {
            stats.failed++;
            failedFiles.push({ file: srcFile, reason: err.message });
            console.warn("[ERROR] " + srcFile + " — " + err.message);
            resolve();
        }));

        worker.on('exit', (code) => {
            once(() => {
                const reason = code === 0 ?
                    'Worker stopped without returning a result' :
                    `Worker stopped with exit code ${code}`;

                stats.failed++;
                failedFiles.push({ file: srcFile, reason });
                console.warn("[ERROR] " + srcFile + " — " + reason);
                resolve();
            })();
        });
    });
}

// Process files in parallel with concurrency limit
async function processFilesInParallel(files) {
    let currentIndex = 0;
    const workers = [];

    for (let i = 0; i < MAX_PARALLEL; i++) {
        workers.push(
            (async () => {
                while (currentIndex < files.length) {
                    const index = currentIndex++;
                    if (index < files.length) {
                        const fileTask = files[index];
                        await processFile(fileTask.src, fileTask.dst);
                    }
                }
            })()
        );
    }

    await Promise.all(workers);
}

function collectFiles(srcDir, relBase, dstBase, fileList = []) {
    const items = fs.readdirSync(srcDir);
    for (const item of items) {
        const srcPath = path.join(srcDir, item);
        let stat;

        try {
            stat = fs.statSync(srcPath);
        } catch (e) {
            if (e.code === 'ENOENT') continue;
            throw e;
        }

        if (stat.isDirectory()) {
            collectFiles(srcPath, relBase, dstBase, fileList);
        } else {
            fileList.push({
                src: srcPath,
                dst: path.join(dstBase, path.relative(relBase, srcPath))
            });
        }
    }
    return fileList;
}

function getAllFilesInDir(dir, fileList = []) {
    if (!fs.existsSync(dir)) return fileList;

    let items;

    try {
        items = fs.readdirSync(dir);
    } catch (e) {
        if (e.code === 'ENOENT') return fileList;
        throw e;
    }

    for (const item of items) {
        const fullPath = path.join(dir, item);
        let stat;

        try {
            stat = fs.statSync(fullPath);
        } catch (e) {
            if (e.code === 'ENOENT') continue;
            throw e;
        }

        if (stat.isDirectory()) {
            getAllFilesInDir(fullPath, fileList);
        } else {
            fileList.push(fullPath);
        }
    }
    return fileList;
}

function syncDeleteOldFiles(expectedFiles) {
    const
        expectedSet = new Set(expectedFiles.map(f => path.normalize(f.dst))),
        existingFiles = getAllFilesInDir(outputDir);

    for (const filePath of PRESERVED_OUTPUT_FILES) {
        expectedSet.add(path.normalize(filePath));
    }

    for (const dir of inputDirs) {
        if (fs.existsSync(dir)) {
            expectedSet.add(path.normalize(path.join(outputDir, path.basename(dir) + '.die-db')));
        }
    }

    let deletedCount = 0;
    for (const existingFile of existingFiles) {
        const normalized = path.normalize(existingFile);

        // Skip cache file itself
        if (normalized === path.normalize(CACHE_FILE)) {
            continue;
        }

        if (!expectedSet.has(normalized)) {
            try {
                fs.unlinkSync(existingFile);
                console.log("[DELETED] " + path.relative(process.cwd(), existingFile));
                deletedCount++;
            } catch (e) {
                console.warn("[DELETE FAILED] " + existingFile + " — " + e.message);
            }
        }
    }

    deleteEmptyDirs(outputDir);

    return deletedCount;
}


function createDieDb(srcDir, archivePath) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(archivePath);
        const archive = archiver('zip', {
            zlib: { level: 9 }
        });

        output.on('close', () => resolve(archive.pointer()));
        output.on('error', reject);
        archive.on('error', reject);

        archive.pipe(output);
        archive.directory(srcDir, false);
        archive.finalize();
    });
}

function deleteEmptyDirs(dir) {
    if (!fs.existsSync(dir)) return;

    let items;

    try {
        items = fs.readdirSync(dir);
    } catch (e) {
        if (e.code === 'ENOENT') return;
        throw e;
    }

    for (const item of items) {
        const fullPath = path.join(dir, item);
        let stat;

        try {
            stat = fs.statSync(fullPath);
        } catch (e) {
            if (e.code === 'ENOENT') continue;
            throw e;
        }

        if (stat.isDirectory()) {
            deleteEmptyDirs(fullPath);
        }
    }

    try {
        if (fs.readdirSync(dir).length === 0 && dir !== outputDir) {
            fs.rmdirSync(dir);
        }
    } catch (e) {
        if (e.code !== 'ENOENT' && e.code !== 'ENOTEMPTY') throw e;
    }
}

(async () => {
    console.log(`[i] Processing with ${MAX_PARALLEL} parallel workers...\n`);

    const allFiles = [];

    for (const dir of inputDirs) {
        if (fs.existsSync(dir)) {
            const dstSubdir = path.join(outputDir, path.basename(dir));
            collectFiles(dir, dir, dstSubdir, allFiles);
        } else {
            console.warn("[SKIP] Dir not found: " + dir);
        }
    }

    console.log(`[i] Found ${allFiles.length} files to process\n`);
    stats.total = allFiles.length;

    // Delete obsolete files FIRST (before any other output)
    stats.deleted = syncDeleteOldFiles(allFiles);
    if (stats.deleted > 0) {
        console.log(`[i] Deleted ${stats.deleted} obsolete files\n`);
    }

    // Load cache and filter files unchanged by mtime
    const
        cache = loadCache(),
        newCache = new Map(),
        toProcess = [];

    const compilerFingerprint = computeCompilerFingerprint();
    const isCompilerCacheValid = cache.get(COMPILER_CACHE_KEY) === compilerFingerprint;

    newCache.set(COMPILER_CACHE_KEY, compilerFingerprint);

    for (const f of allFiles) {
        try {
            const st = fs.statSync(f.src);
            const fingerprint = `${Math.floor(st.mtimeMs)}:${st.size}`;
            const key = computeKeyForPath(f.src);

            newCache.set(key, fingerprint);

            // Check if file unchanged
            if (isCompilerCacheValid && cache.get(key) === fingerprint && fs.existsSync(f.dst)) {
                stats.skipped++;
                continue;
            }
        } catch (e) {
            // couldn't stat - process to be safe
        }
        toProcess.push(f);
    }

    if (stats.skipped > 0) {
        console.log(`\n[i] Skipped ${stats.skipped} unchanged files (cache)`);
    }

    await processFilesInParallel(toProcess);

    for (const failedFile of failedFiles) {
        newCache.delete(computeKeyForPath(failedFile.file));
    }

    // A complete cache hit already has exactly the cache state we need. Avoid the
    // relatively expensive maximum-quality Brotli pass when nothing has changed.
    if (toProcess.length > 0 || stats.deleted > 0 || !isCompilerCacheValid) {
        saveCache(newCache);
    }

    // Create .die-db archives for each processed directory
    console.log("[i] Creating .die-db archives...\n");
    for (const dir of inputDirs) {
        const srcDir = path.join(outputDir, path.basename(dir));
        if (!fs.existsSync(srcDir)) continue;

        const archivePath = path.join(outputDir, path.basename(dir) + '.die-db');

        if (toProcess.length === 0 && stats.deleted === 0 && fs.existsSync(archivePath)) {
            console.log(`[SKIP] ${archivePath}`);
            continue;
        }

        try {
            const bytes = await createDieDb(srcDir, archivePath);
            console.log(`[PACKED] ${archivePath} (${(bytes / 1024).toFixed(1)} KB)`);
        } catch (e) {
            stats.failed++;
            failedFiles.push({ file: archivePath, reason: e.message });
            console.warn(`[PACK FAILED] ${archivePath} — ${e.message}`);
        }
    }

    let report = "\n[V] Done!\n" +
        `— Total:     ${stats.total}\n` +
        `— Minified:  ${stats.minified}\n` +
        `— Copied:    ${stats.copied}\n` +
        `— Failed:    ${stats.failed}\n` +
        `— Skipped:   ${stats.skipped}\n` +
        `— Deleted:   ${stats.deleted}\n`;

    if (copiedFiles.length > 0) {
        report += "\n[I] Copied (unsupported extension):\n" + copiedFiles.map((f) => " • " + f).join("\n") + "\n";
    }

    if (failedFiles.length > 0) {
        report += "\n[X] Failed:\n" + failedFiles.map((f) => ` • ${f.file} — ${f.reason}`).join("\n") + "\n";
    }

    console.log(report);

    if (stats.failed > 0) {
        process.exitCode = 1;
    }

    console.log('');
})();
