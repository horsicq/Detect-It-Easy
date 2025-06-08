const
  fs = require('fs'),
  path = require('path'),
  terser = require('terser');

const
  inputDirs = ['db', 'db_custom', 'db_extra'],
  outputDir = 'dbs_min';

function shouldMinify(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.sg' || ext === '';
}

async function processFile(srcFile, dstFile) {
  let text;
  try {
    text = fs.readFileSync(srcFile, 'utf8');
  } catch (e) {
    fs.mkdirSync(path.dirname(dstFile), { recursive: true });
    fs.copyFileSync(srcFile, dstFile);
    console.log('[COPIED] ' + srcFile);
    return;
  }

  if (shouldMinify(srcFile)) {
    try {
      const minified = await terser.minify(text, {
        compress: true,
        mangle: { toplevel: false },
        format: { semicolons: false, beautify: false }
      });
      if (minified.error) throw minified.error;
      fs.mkdirSync(path.dirname(dstFile), { recursive: true });
      fs.writeFileSync(dstFile, minified.code, 'utf8');
      console.log('[MINIFIED] ' + srcFile);
    } catch (e) {
      // Если что-то пошло не так, просто копируем исходный файл
      fs.mkdirSync(path.dirname(dstFile), { recursive: true });
      fs.writeFileSync(dstFile, text, 'utf8');
      console.warn('[SKIP/BROKEN] ' + srcFile + ' (minify failed: ' + e.message + ')');
    }
  } else {
    fs.mkdirSync(path.dirname(dstFile), { recursive: true });
    fs.writeFileSync(dstFile, text, 'utf8');
    console.log('[COPIED] ' + srcFile);
  }
}

async function walk(srcDir, relBase, dstBase) {
  for (const item of fs.readdirSync(srcDir)) {
    const
      srcPath = path.join(srcDir, item),
      relPath = path.relative(relBase, srcPath),
      dstPath = path.join(dstBase, relPath);

    const stat = fs.statSync(srcPath);
    if (stat.isDirectory()) {
      await walk(srcPath, relBase, dstBase);
    } else {
      await processFile(srcPath, dstPath);
    }
  }
}

(async () => {
  for (const dir of inputDirs) {
    if (fs.existsSync(dir)) {
      const dstSubdir = path.join(outputDir, path.basename(dir));
      await walk(dir, dir, dstSubdir);
    } else {
      console.warn('[SKIP] Dir not found: ' + dir);
    }
  }
  console.log('✅ Done!');
})();