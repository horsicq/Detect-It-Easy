# Contributing to Detect-It-Easy

Welcome in contributing to Detect-It-Easy!

## Ask Questions

Curiosity is key to driving the project forward. If you have questions or ideas for improvement, don't hesitate to reach out. You can start a discussion by [opening a new issue](https://github.com/horsicq/Detect-It-Easy/issues/new).

## How to Report Issues

To report bugs and errors, please [open a new issue](https://github.com/horsicq/Detect-It-Easy/issues/new) on GitHub. Include detailed steps to reproduce the bug, along with any relevant stack traces, error messages, or affected files.

## Feature Requests

If you have ideas for new features or enhancements, feel free to [open a new issue](https://github.com/horsicq/Detect-It-Easy/issues/new) to discuss them. Your input is valuable in shaping the future of the project.

## Coding Standards and Formatting Rules

To maintain code quality and consistency across the project, please adhere to the following guidelines when contributing code:

-   **Language and Style**: The project primarily uses DiE-JS. Follow the existing code style.
-   **Formatting**: Follow [CODE-FORMATTING.md](CODE-FORMATTING.md). Format every `.sg` rule and script module as JavaScript with Microsoft Visual Studio Code's built-in **TypeScript and JavaScript Language Features** formatter. Use 4 spaces and no tabs.
-   **Commits**: Write descriptive commit messages. Use the imperative mood (e.g., "Fix bug in file parser" instead of "Fixed bug").
-   **Testing**: Include unit tests for new features or bug fixes where applicable. Ensure they are compilable!

## Detection Rule Performance Requirements

Every new or substantially changed detection rule must reject irrelevant files as cheaply as possible before it performs byte-pattern scanning. Conditions are evaluated from left to right, so their order is part of the rule's performance design, not merely a matter of style.

-   Put inexpensive format, architecture, header, directory, section-count, section-name, size, entry-point, import, export, resource, and other structural checks first.
-   Add relevant antipatterns and exclusions before an expensive positive signature search. A common marker without an antipattern is not sufficient when legitimate files can contain the same data.
-   Calls such as `findSignature()`, `isSignaturePresent()`, `isSignatureInSectionPresent()`, and similar byte-search helpers must never be the first line of defence.
-   Restrict every search to the smallest meaningful section, resource, overlay, header range, or other bounded region. Do not scan the entire file when a narrower range is available.
-   Cache offsets, sizes, section objects, and other values that would otherwise be calculated repeatedly.

These search functions are allowed only after cheap preconditions have reduced the candidate set. A rule that begins with an expensive signature scan, omits applicable antipatterns, or performs an avoidable whole-file search will be rejected.

### ❌ Bad: formatting and an unguarded whole-file scan

```js
function detect() {
    if(PE.findSignature(0,PE.getSize(),"'Example marker'")!==-1)
    {
        bDetected = true;
    }
return result();
}
```

This rule scans every candidate file immediately, has no cheap precondition or antipattern, and uses a brace layout that is not produced by the required VS Code formatter.

### ✅ Good: cheap gates before a bounded signature search

```js
function detect() {
    if (PE.compareEP("60909090E8........") &&
        PE.getNumberOfSections() === 3 &&
        PE.getEntryPointSection() === PE.nLastSection &&
        PE.isSignaturePresent(PE.getEntryPointOffset(), 0x200, "'Example marker'")) {
        bDetected = true;
    }

    return result();
}
```

Here the small entry-point comparison, structural checks, and antipattern reject most files before the bounded 512-byte search is reached.

## New Detection Rule Pull Requests

A pull request that adds a detection rule must give maintainers enough material to reproduce and independently verify the detection. Include:

-   Representative test samples, or stable download links accepted by the maintainers, for every product, family, format, version, or variant that the rule claims to cover.
-   The expected DiE result for each sample and a short explanation of which branch of the rule it exercises.
-   Reliable sources that identify the samples and support the claimed name, version, authorship, or behavior. Suitable sources include an official product page or archive, vendor documentation, a public repository, technical research, or another independently checkable reference.
-   Relevant clean or confusing samples for antipattern and false-positive testing when the positive marker can also occur in unrelated software.

Do not rely on a filename, an unverifiable attribution, or a single screenshot as proof of coverage. If maintainers cannot obtain the samples or verify the supporting sources, the rule cannot be tested properly and may be rejected.

## Guidelines for Translations or Code Contributions

We welcome contributions to translations and code to make Detect-It-Easy accessible to a global audience:

-   **Translations**: If you'd like to add or update translations, fork the XTranslation repository and work on the relevant language files (typically in the `dicts/` directory). Ensure translations are accurate and culturally appropriate. Test them in the application to verify context. Use poedit for translating languages!
-   **Process**: Submit changes via a pull request (see below).
-   **Quality**: Proofread your contributions for grammar and clarity. Maintain consistency with the existing tone and style.

## How to Submit Pull Requests

1. Fork the repository on GitHub.
2. Create a new branch for your changes (e.g., `feature/new-detection-rule` or `fix/bug-123`).
3. Make your changes, ensuring they follow the coding standards and guidelines above.
4. Test your changes thoroughly.
5. Commit your changes with a clear, descriptive message.
6. Push your branch to your fork and [open a pull request](https://github.com/horsicq/Detect-It-Easy/compare) against the main branch.
7. In the pull request description, explain what changes you made and why. Reference any related issues. New detection rules must also include the required test samples, expected results, and verification sources described above.
8. Be responsive to feedback from maintainers and make requested revisions.

Pull requests will be reviewed, and once approved, merged into the project. Thank you for helping improve **Detect It Easy**!
