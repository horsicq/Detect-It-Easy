const fs = require("fs");
const path = require("path");
const { Worker } = require("worker_threads");

const inputDirs = ["db", "db_custom", "db_extra"];
const outputDir = "dbs_min";
const MAX_PARALLEL = 6; // Reduced from 16 to prevent resource exhaustion

var stats = {
    total: 0,
    minified: 0,
    copied: 0,
    failed: 0,
};

const failedFiles = [];
const copiedFiles = [];

function processFile(srcFile, dstFile) {
    return new Promise((resolve) => {
        const worker = new Worker(path.join(__dirname, 'worker.js'), {
            workerData: { srcFile, dstFile },
            resourceLimits: {
                maxOldGenerationSizeMb: 2048,
                maxYoungGenerationSizeMb: 512
            }
        });

        let isResolved = false;

        const cleanup = () => {
            if (!isResolved) {
                isResolved = true;
                worker.terminate().catch(() => { });
                resolve();
            }
        };

        worker.on('message', (result) => {
            stats.total++;

            if (result.type === 'minified') {
                stats.minified++;
                console.log("[MINIFIED] " + result.srcFile);
            } else if (result.type === 'copied') {
                stats.copied++;
                copiedFiles.push(result.srcFile);
                console.log("[COPIED] " + result.srcFile);
            } else if (result.type === 'failed') {
                stats.failed++;
                failedFiles.push({ file: result.srcFile, reason: result.error });
                console.warn("[FAILED] " + result.srcFile + " — " + result.error);
            } else {
                stats.failed++;
                failedFiles.push({ file: result.srcFile, reason: "Read error: " + result.error });
                console.warn("[ERROR/READ] " + result.srcFile + " — " + result.error);
            }

            cleanup();
        });

        worker.on('error', (err) => {
            stats.failed++;
            failedFiles.push({ file: srcFile, reason: err.message });
            console.warn("[ERROR] " + srcFile + " — " + err.message);
            cleanup();
        });

        worker.on('exit', (code) => {
            if (code !== 0 && !isResolved) {
                stats.failed++;
                failedFiles.push({ file: srcFile, reason: `Worker stopped with exit code ${code}` });
                console.warn("[ERROR] " + srcFile + " — Worker stopped with exit code " + code);
            }
            cleanup();
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

        const stat = fs.statSync(srcPath);
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

    await processFilesInParallel(allFiles);

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
