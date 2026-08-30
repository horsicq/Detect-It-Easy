# USE MICROSOFT VISUAL STUDIO CODE'S BUILT-IN JAVASCRIPT FORMATTER

All detection rules and script modules in `db`, `db_extra`, and `db_custom` are DiE-JS. Format them as JavaScript with the formatter built into **Microsoft Visual Studio Code**.

Do not use an extension-specific formatter as the primary formatter for `.sg` files. In VS Code, the expected formatter is shown as **TypeScript and JavaScript Language Features** and has the identifier `vscode.typescript-language-features`. The repository `.prettierrc` keeps auxiliary tooling broadly compatible, but it does not replace the built-in VS Code formatter for DiE-JS.

This document defines the style for new rules and for code touched by a change. Some old database files predate the standard and contain legacy formatting. Do not copy a legacy exception into new code, and do not reformat an unrelated large file merely to make it match this document.

The [PE heuristic analyzer](db/PE/__GenericHeuristicAnalysis_By_DosX.7.sg) is a reference for spacing only. It is a specialized module maintained exclusively by its author: do not copy its internal data structures, detector blocks, or result-building code into ordinary rules, and do not modify it as part of unrelated formatting work.

## VS Code setup

Associate `.sg` files with JavaScript, select the built-in formatter, and run **Format Document** (`Shift+Alt+F` on Windows/Linux) before every commit.

The following VS Code settings reproduce the intended baseline:

```json
{
    "files.associations": {
        "*.sg": "javascript"
    },
    "[javascript]": {
        "editor.defaultFormatter": "vscode.typescript-language-features",
        "editor.detectIndentation": false,
        "editor.formatOnSave": true,
        "editor.insertSpaces": true,
        "editor.tabSize": 4
    },
    "javascript.format.enable": true,
    "javascript.format.insertSpaceAfterCommaDelimiter": true,
    "javascript.format.insertSpaceAfterFunctionKeywordForAnonymousFunctions": true,
    "javascript.format.insertSpaceAfterKeywordsInControlFlowStatements": true,
    "javascript.format.insertSpaceAfterOpeningAndBeforeClosingNonemptyBraces": true,
    "javascript.format.insertSpaceAfterSemicolonInForStatements": true,
    "javascript.format.insertSpaceBeforeAndAfterBinaryOperators": true,
    "javascript.format.insertSpaceBeforeFunctionParenthesis": false,
    "javascript.format.placeOpenBraceOnNewLineForControlBlocks": false,
    "javascript.format.placeOpenBraceOnNewLineForFunctions": false,
    "javascript.format.semicolons": "insert"
}
```

If **Format Document With...** offers several choices, choose **Configure Default Formatter**, then select **TypeScript and JavaScript Language Features**. Prettier, Beautify, ESLint fixes, and other extensions must not silently take ownership of `.sg` formatting.

The formatter handles indentation and horizontal spacing. It intentionally preserves much of the author's vertical spacing, so the blank-line rules below still need to be applied by hand.

## Canonical standalone rule

Use this as the starting point for a normal detection rule:

```js
// Detect It Easy: detection rule file
// Author: Your Name <you@example.com>

// Optional reference URL
meta("compiler", "Example Compiler");

function detect() {
    if (PE.isSectionNamePresent(".lz-algo")) {
        sVersion = "1.0";
        sOptions = "LZMA";
        bDetected = true;
    }

    sLang = "C/C++";

    return result();
}
```

Remove fields that the rule does not need. Do not leave empty assignments merely to resemble the template.

## File order

A standalone rule is laid out in this order:

1. `// Detect It Easy: detection rule file` on the first line.
2. One empty line. (optional, but not recommended)
3. Author or co-author comments, kept together without empty lines between them.
4. One empty line.
5. Optional references or short provenance comments.
6. `meta("type", "name");` immediately after the reference block.
7. One empty line.
8. Optional `includeScript("module");` calls, one per line and kept together.
9. One empty line.
10. `function detect() { ... }`.
11. Helper functions, if required.

If there is no author block, reference block, `meta()`, or include block, omit that block and its associated separator. Never create several empty sections just because an optional part is absent.

Example with a shared module:

```js
// Detect It Easy: detection rule file
// Author: Your Name <you@example.com>

// Reference URL
meta("compiler", "Example Compiler");

includeScript("ExampleSharedModule");

function detect() {
    if (bExampleCompiler) {
        bDetected = true;
    }

    return result();
}
```

## Result fields

The engine provides the following result variables. Do not declare local variables with the same names.

| Field       | Rule                                                                                                                                                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bDetected` | Set to `true` only after the detection conditions have succeeded. A normal rule does not produce a result without it.                                                                                                                                                                      |
| `sName`     | Optional runtime override for the name supplied by `meta()`. Use it when one file contains several detectable variants.                                                                                                                                                                    |
| `sVersion`  | Optional version or build text. Keep it short and do not repeat the product name.                                                                                                                                                                                                          |
| `sOptions`  | Optional qualifiers such as architecture, mode, compiler target, modification state, or embedded component.                                                                                                                                                                                |
| `sLang`     | Optional language result. This field is rare and belongs mainly in compiler rules. Place it at the end of `detect()`, immediately before the empty line that precedes `return result();`. Libraries, packers, and other rules may set it only when the evidence is strong and unambiguous. |
| `sType`     | Very rare category override for a multi-purpose rule. Prefer a correct `meta()` category in ordinary rules.                                                                                                                                                                                |

In the current database, roughly four out of five `sLang` assignments belong to compiler rules. Do not set `sLang` simply because a tool is commonly associated with a language.

Assign ordinary descriptive fields before `bDetected`:

```js
if (matched) {
    sVersion = "2.0";
    sOptions = "modified";
    bDetected = true;
}
```

`sLang` is the deliberate exception. Assign it once, after the detection logic and immediately before the final blank line and `return result();`:

```js
    sLang = "Rust";

    return result();
}
```

End a normal `detect()` function exactly like this:

```js
    }

    return result();
}
```

There is one empty line before `return result();`. There is no empty line between `return result();` and the closing brace. This spacing is required even when the detection body is short.

## Indentation

-   Use **4 spaces** for every indentation level.
-   Never use tabs. The database formatting workflow converts tabs to four spaces, but contributors must not rely on CI to repair them.
-   A nested block adds exactly four spaces.
-   Continuation lines add one additional indentation level unless a deeper syntactic level requires more.
-   `case` and `default` labels are indented once inside `switch`; their statements are indented once more.

```js
switch (value) {
    case 1:
        sVersion = "1.0";
        break;
    default:
        break;
}
```

Do not align unrelated assignments with large runs of spaces. Indentation describes structure; it is not a table-layout tool.

## Spaces

The following forms are required:

| Construct            | Required form                                                  |
| -------------------- | -------------------------------------------------------------- |
| Control-flow keyword | `if (condition)`, `for (...)`, `while (...)`, `switch (value)` |
| Named function       | `function detect()`                                            |
| Anonymous function   | `function () { ... }`                                          |
| Function call        | `result()`, not `result ()`                                    |
| Array access         | `items[index]`, not `items [index]` or `items[ index ]`        |
| Unary operators      | `!detected`, `i++`, `--count`                                  |
| Binary operators     | `left === right`, `offset + size`, `flags & mask`              |
| Assignment           | `sVersion = "1.0";`                                            |
| Ternary              | `condition ? yes : no`                                         |
| Comma                | `call(first, second)`                                          |
| Object property      | `{ name: ".text", size: 512 }`                                  |
| Line comment         | `// Comment text`                                              |
| Inline comment       | `statement; // Explanation`                                    |

Rules derived from this table:

-   Put one space after `if`, `for`, `while`, `switch`, and `catch` before `(`.
-   Do not put a space between a function name and `(`.
-   Put one space on both sides of assignment, comparison, arithmetic, bitwise, and logical operators.
-   Do not put spaces just inside `()` or `[]`.
-   Put one space after each comma and none before it.
-   Put one space after the colon in an object property and none before it.
-   Opening braces stay on the same line as the function or control statement.
-   Write `} else {`, `} else if (...) {`, `} catch (...) {`, and `} finally {` on one line.
-   Use double quotes for strings. Single quotes inside a DiE byte signature are signature syntax and remain inside the surrounding double-quoted JavaScript string.
-   Terminate statements with semicolons.
-   Prefer strict equality (`===` and `!==`) in new code unless type coercion is an intentional, documented part of the check.
-   Never leave trailing spaces at the end of a line.

## Braces and control flow

Use braces for every multi-line control block:

```js
if (matched) {
    sVersion = "1.0";
    bDetected = true;
} else if (fallbackMatched) {
    bDetected = true;
}
```

A single short guard or assignment may remain on one line when it is genuinely easier to read:

```js
if (!section) return false;
if (matched) bDetected = true;
```

Do not place two unrelated statements on one line. Do not compress a multi-branch `if`, loop, or `switch` merely to reduce line count.

## Line wrapping

VS Code does not need to force every signature string below a fixed column. Long byte signatures, regular expressions, URLs, and API calls may stay on one line when splitting them would obscure the pattern. Wrap logical structure, not arbitrary character counts.

For a multi-line condition, keep the first condition after `if (`. Continue the following conditions one indentation level deeper than the `if` statement, and keep `) {` on the final condition line:

```js
if (PE.getNumberOfSections() > 3 &&
    PE.getEntryPointSection() === PE.nLastSection &&
    PE.getImportSection() === 2) {
    bDetected = true;
}
```

Keep nested grouping explicit without moving the outer opening parenthesis onto a separate line:

```js
if ((!PE.is64() && PE.getNumberOfSections() === 3) ||
    (PE.is64() && PE.getNumberOfSections() === 4)) {
    bDetected = true;
}
```

For a long declaration, place the comma at the end of the current declaration and align following names one indentation level deeper:

```js
var sectionOffset = PE.getSectionFileOffset(index),
    sectionSize = PE.getSectionFileSize(index),
    sectionName = PE.getSectionName(index);
```

Split a structured value across lines when each field carries separate information:

```js
var sectionInfo = {
    name: PE.getSectionName(index),
    fileOffset: PE.getSectionFileOffset(index),
    fileSize: PE.getSectionFileSize(index)
};
```

Do not add a comma after the last array item, object property, parameter, or argument solely for formatting. Preserve a trailing comma only when the surrounding module already uses it intentionally.

## Blank lines

Blank lines are part of the project style; the built-in formatter will not create all of them for you.

For an ordinary standalone rule:

-   Use one empty line between the file header, attribution, metadata/include block, and `detect()`.
-   Use one empty line between independent logical steps inside `detect()`.
-   Keep tightly related assignments together with no empty lines between them.
-   Use one empty line before a nested check when it starts a distinct decision.
-   Use exactly one empty line before the final `return result();`.
-   Do not start a short function with an empty line immediately after `{`.
-   Do not put an empty line between `return result();` and `}`.

For a large script module with clearly separated independent passes:

-   Use **three empty lines** between top-level functions, JSDoc blocks, or `#region` sections.
-   Use **four empty lines** between major independent detector blocks inside a long scan function.
-   Use one empty line inside a detector block to separate declaration, condition, result construction, and logging.
-   Keep the wider three/four-line rhythm out of small standalone signature rules.

The last visible line of a file is the closing `}`. Do not add an empty line after it. A terminal line-ending character may be preserved by the editor or Git; it is not the same as an extra blank line. Do not create mixed LF/CRLF endings or make line-ending-only changes.

## Arrays and objects

Short arrays may stay on one line:

```js
var names = [".text", ".rdata", ".data"];
```

Use one item per line when entries contain tuples, comments, regular expressions, or long signatures:

```js
var signatures = [
    ["1.0", [".text", ".rdata"]],
    ["2.0", [/^\.textbss$/, ".data"]]
];
```

An entry schema must be represented by the correct nesting. If element `[1]` is a list of expected section names, keep all of those names inside that list:

```js
// Correct
["1.0", [".text", ".rdata"]];

// Wrong: ".rdata" is no longer part of element [1]
["1.0", ".text", ".rdata"];
```

Use a multi-line object when it represents an ordinary structured value with several meaningful fields:

```js
var scanRange = {
    offset: PE.getEntryPointOffset(),
    size: 0x200
};
```

## Variables and names

-   Use `const` when the binding is not reassigned.
-   Use `var` for mutable locals and for compatibility with the DiE-JS runtime used by existing modules.
-   Avoid `let` in new database rules unless the target runtime and the surrounding module already require and support it.
-   Use descriptive `camelCase` names for locals and functions.
-   Boolean names should normally begin with `is`, `has`, `can`, or `should`.
-   Constants shared across a module may use an established module-specific convention; do not rename engine API constants for style alone.
-   Do not shadow engine result fields such as `sName`, `sVersion`, `sOptions`, `sLang`, `sType`, or `bDetected`.

## Comments and references

-   Start a normal line comment with `// `: two slashes followed by one space.
-   Place a source URL directly above the rule or check it supports.
-   Explain why a condition exists, not what an obvious assignment does.
-   Use inline comments sparingly and separate them from code with one space.
-   Preserve comments embedded in signature strings; they are data, not JavaScript formatting.
-   Use JSDoc for reusable helpers whose parameters, return value, or side effects are not immediately obvious.
-   Keep `@param`, `@returns`, and `@throws` descriptions grammatical and synchronized with the code.

```js
/**
 * Checks whether all expected markers are present.
 *
 * @param {Array} markers - Marker names to check.
 * @returns {boolean} True when every marker is present.
 */
function areMarkersPresent(markers) {
    for (var i = 0; i < markers.length; i++) {
        if (!PE.isSectionNamePresent(markers[i])) return false;
    }

    return true;
}
```

## Detection-code hygiene

Formatting cannot rescue a weak rule. New detection code should also follow these rules:

-   Cheap structural checks and relevant antipatterns are mandatory before expensive byte searches.
-   Never use `findSignature()`, `isSignaturePresent()`, `isSignatureInSectionPresent()`, or a similar search helper as the first line of defence. Conditions run from left to right, so put cheap gates first.
-   Bound every content search to the smallest meaningful section, resource, overlay, or header region.
-   Cache values that are expensive or used repeatedly.
-   Combine weak indicators instead of presenting one common string as a definitive family match.
-   Add exclusions or antipatterns whenever a legitimate producer can share a marker.
-   Sanitize names read from malformed files before placing them in output.
-   Do not edit generated files in `dbs_min` by hand. Regenerate them with the repository tooling.

Rules that put an expensive signature scan first, omit applicable antipatterns, or perform an avoidable whole-file search are rejected during review. See the mandatory [detection-rule performance requirements](CONTRIBUTING.md#detection-rule-performance-requirements).

## Exceptions

Minified modules, generated database output, vendored code, and large legacy rules may also differ. Touch only the lines needed for the change unless a maintainer explicitly requests a full cleanup.

## Before committing

1. Open every changed `.sg` file as JavaScript in VS Code.
2. Run **Format Document** with **TypeScript and JavaScript Language Features**.
3. Confirm indentation is four spaces and contains no tabs.
4. Remove trailing whitespace.
5. Restore the required blank line before every final `return result();`.
6. Check that `meta()`, includes, `detect()`, and helpers are in the expected order.
7. Confirm ordinary optional result fields are assigned before `bDetected = true`.
8. If the rule sets `sLang`, place it after the detection logic and immediately before the blank line preceding `return result();`.
9. Compile or minify the changed scripts to catch syntax errors.
10. Review the diff for unrelated formatting churn and mixed line endings.
