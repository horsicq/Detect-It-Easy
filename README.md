![](docs/logo_text.png)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=NF3FBD3KHMXDN)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/horsicq/DIE-engine.svg)](http://ntinfo.biz)
[![GitHub All Releases](https://img.shields.io/github/downloads/horsicq/DIE-engine/total.svg)](http://ntinfo.biz)
[![gitlocalized](https://gitlocalize.com/repo/4736/whole_project/badge.svg)](https://github.com/horsicq/XTranslation)

**Detect It Easy (DiE)** is a powerful tool for file type identification, popular among **malware analysts**, **cybersecurity experts**, and **reverse engineers** worldwide. Supporting both **signature-based** and **heuristic analysis**, DiE enables efficient file inspections across a broad range of platforms, including **Windows, Linux, and MacOS**. Its adaptable, script-driven detection architecture makes it one of the most versatile tools in the field, with a comprehensive list of supported OS images.

## 🚀 Getting started

-   **[💎 Download release/beta](https://github.com/horsicq/DIE-engine/releases)**
-   **[🧪 DiE API Library (for Developers)](https://github.com/horsicq/die_library)**
-   [📋 Changelog](https://github.com/horsicq/Detect-It-Easy/blob/master/changelog.txt)
-   [💬 Contribute to Translations](https://github.com/horsicq/XTranslation)

![Screenshot](docs/1.png)

## 💡 Why use Detect It Easy?

Detect It Easy’s **flexible signature system** and **scripting capabilities** make it an essential tool for **malware analysis** and **digital forensics**. With traditional static analyzers often limited in scope and prone to false positives, DiE’s customizable design enables precise integration of new detection logic, ensuring reliable results across diverse file types.

![Screenshot](docs/2.png)

### Key advantages:

-   **Flexible Signature Management**: Easily create, modify, and optimize detection scripts (rules).
-   **Cross-Platform Support**: Runs on Windows, Linux, and MacOS.
-   **Minimal False Positives**: Combined signature and heuristic analysis ensures high detection accuracy.

## 🧠 Heuristic engine

### PE analysis that goes beyond a signature match

A signature can tell you what a file resembles. The [Generic Heuristic Analysis engine](db/PE/__GenericHeuristicAnalysis_By_DosX.7.sg) goes further: it tries to explain what is unusual about the file and why it deserves a closer look.

With heuristic scanning enabled, DiE makes a series of independent passes over native and managed PE images. The file is never launched. Instead, the analyzer works with headers, data directories, sections, imports, exports, resources, .NET metadata, bytecode, overlays, debug records, and code around the entry point. This makes it useful both when an exact signature is known and when a sample has been modified enough to evade ordinary identification.

One of these passes performs **surface-level emulation of native instructions around the entry point**. It is deliberately lightweight rather than a sandbox or full CPU emulator, but it is enough to expose unusual instruction sequences, proxy jumps, stack tricks, NOP padding, hidden TLS entry points, and other patterns often left by packers or hand-written stubs.

Here is what currently goes into a full PE scan:

|     | Area                         | What is checked                                                                                                                                                                                                                                                                            |
| --: | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
|  🧩 | **.NET obfuscation**         | Modified managed entry points, odd CLR constructors and sections, control-flow tricks, integer confusion, encrypted strings, invalid opcodes, anti-tamper, fake metadata, watermarks, and virtualization-like code.                                                                        |
|  🕵️ | **.NET anti-analysis**       | Anti-debug and anti-dump code; checks aimed at dnSpy, ILSpy, SandBoxie, Cuckoo, Wine, VMs, and some security products.                                                                                                                                                                     |
|  🧱 | **Native anomalies**         | DOS area, IAT/EAT, TLS, imports and exports, section permissions, RWX memory, image flags, linker values, empty directories, and suspicious entry-point placement.                                                                                                                         |
|  📦 | **Packers and protectors**   | Packers, cryptors, SFX archives, RunPE-like behavior, compression and crypto clues, overlays, resources, .NET object sets, high entropy, embedded PE files, and damaged unpacking results. This pass also uses the large database of positional import hashes and section-name signatures. |
|  🔑 | **Licensing / DRM**          | .NET licensing APIs and attributes, license managers, activation strings, SteamStub, Denuvo markers, and similar traces.                                                                                                                                                                   |
|  🩺 | **Format integrity**         | Broken headers or entry points, bad alignment, relocations, IAT/EAT/resources, CLR metadata and version strings, Authenticode tampering. Quite useful on dumps and half-reconstructed files.                                                                                               |
|  🧾 | **Debug leftovers**          | Debug sections, exported symbols, .NET Native data, absolute or portable PDB paths, embedded PDBs, and Costura.Fody artifacts.                                                                                                                                                             |
|  ☣️ | **Malware-related patterns** | Correlations between imports, strings, bytecode, opcodes, metadata, resources, payload markers, and PE structure. Used for RATs, stealers, lockers, file infectors, hidden payloads, fake system files, and known families.                                                                |
|  🛠️ | **Toolchain / platform**     | Extra compiler, linker, and language clues in verbose mode, plus Windows-facing markers such as AppContainer and Game Definition File data.                                                                                                                                                |
|  🏷️ | **Filename anomalies**       | Missing or custom extensions, legitimate PE extensions other than `.exe`/`.dll`, misleading names, and application images carrying a `.dll` suffix.                                                                                                                                        |

This is not a black-box malware score. DiE reports the evidence it found so that an analyst can distinguish a broken file, an unusual build, a protected commercial application, and a genuinely suspicious sample. A heuristic result is a lead, not automatic proof of malicious intent. Use `--heuristicscan` together with `--verbose` to see the fullest report.

### Malware clues without pretending to be an antivirus

DiE is **not an antivirus**, and the PE heuristic engine is not designed to declare a file safe. It provides no real-time protection or disinfection, and a clean report only means that the enabled rules did not find the static evidence they know how to recognize. Reputation services, an antivirus, dynamic analysis, and manual reverse engineering still answer different questions.

What DiE can do is expose a surprisingly broad range of threat-related clues while the file is still on disk:

-   **Remote-access trojans and backdoors**, including generic RAT patterns and families such as NjRAT, AsyncRAT, NanoCore, Orcus, Gh0st RAT, DarkComet, NetWire, Remcos, BitRAT, and many others.
-   **Stealers and spyware**, including generic stealer scoring, Mars Stealer, Echelon Stealer, StormKitty, and MAX Spyware indicators.
-   **Ransomware, lockers, and destructive malware**, with checks for WannaCry, UX-Locker, Liberium WinLocker, Amp WinLocker, and Olympic Destroyer.
-   **File-infecting viruses.** The current analyzer contains dedicated static infection checks for **Ramnit, Neshta, Slugin, Win9X.CIH, Win9X.Dupator, Parite, and Polip**.
-   **Targeted and unusual threats**, including markers associated with Slingshot APT, Equation Group tooling, RAT injectors, maliciously generated assemblies, and fake or infected system files.
-   **Hidden payloads and delivery techniques**, such as encoded or encrypted executable payloads, PE files concealed in resources or overlays, RunPE-like behavior, suspicious temporary assemblies, anomalous resources, and misleading build metadata.

These are explainable static detections built from entry-point code, import fingerprints, metadata, strings, resources, section structure, and other relationships inside the image. They are valuable leads, but they are not a promise of complete malware-family coverage: modified samples may evade a rule, and an unusual clean program may share part of a suspicious pattern.

### Heuristic results stay visible

Heuristic findings are never silently mixed into ordinary signature matches. Every result produced by the heuristic layer is kept separate and marked with `(Heur)`, so it is always clear which conclusion came from an exact rule and which one was inferred from a combination of evidence.

The analyzer does more than append extra lines. In a few deliberate cases it can reject a misleading result from the main signature database and replace it with a more precise heuristic conclusion. Programming-language detection is a typical example: a compiler signature may suggest C or C++, while stronger structural and runtime evidence identifies Rust. The replacement still carries `(Heur)` and never passes itself off as an exact signature match. The same reconciliation mechanism is used to suppress known fake packer, protector, and dongle signatures left behind by obfuscators.

A protected .NET sample may produce a report like this:

```text
PE32
    Operation system: Windows (95) [I386, 32-bit, GUI]
    Linker: Microsoft Linker (6.0)
    Compiler: VB.NET
    Language: VB.NET
    Library: .NET Framework (CLR 2.0.50727)
    Protector: .NET Reactor (4.8-4.9) [Anti-ILDASM]
    (Heur) Cryptor: Generic [Assembly invoke + RSACryptoServiceProvider + RunPE + Section #2 (".rsrc") compressed + Section #2 (".rsrc") has wrong size + High entropy]
    (Heur) Protection: Obfuscation [Modified managed EP + Anti-ILDASM + Bad namings + Fake .cctor name + Math mutations]
```

For a native executable, signatures and heuristic evidence can complement each other while remaining visibly distinct:

```text
PE32
    Operation system: Windows (95) [I386, 32-bit, GUI]
    Linker: Microsoft Linker (6.0)
    Compiler: Microsoft Visual C/C++ (12.00.8168) [C++/std]
    (Heur) Language: Rust
    Protector: HyperTech Crackproof
    (Heur) Protection: Generic [Strange sections + Stack-push address near EP + Rdtsc near EP + Section #4 ("naN") has RWX + EP-section #4 ("naN") zero padding + IAT directory empty]
    (Heur) Packer: Generic [EntryPoint + Pushal at EP + Last section EP + Imports like UPX (v0.59-0.93) + Sections like fake UPX + Section #0 ("") compressed + High entropy]
    (Heur) Debug data: Contains [Embedded PDB (release)]
```

### Smaller heuristics for everyday files

PE is the largest heuristic module, but it is not the only one shipped with DiE:

-   The [JavaScript heuristic](db/Binary/__MiniJavaScriptHeuristic_By_DosX.7.sg) recognizes common JavaScript variants, distinguishes text from bytecode, and spots minified or compiled-looking code without blindly matching content inside ordinary strings.
-   The [file-extension heuristic](db/Binary/__MiniExtensionsHeuristic_By_DosX.7.sg) provides a broad fallback catalogue of formats and programming languages, cross-checking the extension against whether the file is actually textual or binary.
-   The [Batch-script heuristic](db/Binary/__MiniBatchHeuristic_By_DosX.7.sg) catches UTF-16LE obfuscation and non-textual content hidden inside BAT and CMD files.

## 📄 Supported file types

Detect It Easy supports a wide range of executable and archive types, including:

-   **PE** (Portable Executable format for Windows)
-   **ELF** (Executable and Linkable Format for Linux)
-   **APK** (Android Application Package)
-   **IPA** (iOS Application Package)
-   **JAR** (Java Archive)
-   **ZIP** (Compressed archives)
-   **ISO9660** (Optical media format)
-   **DEX** (Dalvik Executable for Android)
-   **MS-DOS** (MS-DOS executable files)
-   **COM** (Simple executable format for DOS)
-   **LE/LX** (Linear Executable for OS/2)
-   **MACH** (Mach-O files for MacOS)
-   **NPM** (JavaScript packages)
-   **Amiga** (Executable format for Amiga computers)
-   **Binary** (Other unclassified files)

And that's not all... The list is expanding as the tool is updated

Unknown formats undergo heuristic analysis, providing identification for both known and unrecognized files.

## 🔑 Key features

-   **Flexible Signature Management**: Define or modify detection rules.
-   **Scripted Detection**: Use a JavaScript-like scripting language (DiE-JS ES5 runtime) for custom detection algorithms.
-   **Cross-Platform Compatibility**: Available for Windows, Linux, and MacOS.
-   **Reduced False Positives**: Combines signature and heuristic scanning for accuracy.

## 📥 Installation

### 📦 Install via package managers

-   **Windows**:

    -   [Chocolatey](https://community.chocolatey.org/packages/die)
    -   [Microsoft Store](https://apps.microsoft.com/detail/9nq58d7ghb2x)

-   **Linux**:

    -   **Parrot OS**: Package name `detect-it-easy`
    -   **Arch Linux**: AUR package [detect-it-easy-git](https://aur.archlinux.org/packages/detect-it-easy-git/)
    -   **openSUSE**: [OBS](https://build.opensuse.org/package/show/home:mnhauke/detect-it-easy)
    -   **REMnux**: Malware analysis distribution

    [![Packaging status](https://repology.org/badge/vertical-allrepos/detect-it-easy.svg)](https://repology.org/project/detect-it-easy/versions)

> [!NOTE]
> Use **Detect It Easy** bot via **Telegram** to quickly check files: [**@detectiteasy_bot**](https://t.me/detectiteasy_bot)

### ⚙️ Build from source

See the [BUILD.md](docs/BUILD.md) for detailed instructions.

### 🐳 Docker installation

Run DiE in a Docker container:

```bash
git clone --recursive https://github.com/horsicq/Detect-It-Easy
cd Detect-It-Easy/
docker build . -t horsicq:diec
```

## 🖥️ Usage

**Detect It Easy** offers three versions:

-   **die** - Graphical interface.
-   **diec** - Command-line version for batch processing.
-   **diel** - Lightweight GUI version. (scanner only)

For detailed usage, refer to the [RUN.md](docs/RUN.md).

### 🔎 Example use cases

-   🦠 **Malware Analysis**: Identify file types, packers, or protections. Heuristic engine detects multiple malware and file virus families.
-   🛡 **Security Audits**: Determine executable potential security risks.
-   🔎 **Software Forensics**: Inspect software components and validate compliance.

## 💬 Our community

👋 **Hello! / Привет!** Welcome to the Detect It Easy community!

Have questions, ideas, or just want to chat? Here's where to find us:

-   **GitHub Discussions**: Start a conversation in [Discussions](https://github.com/horsicq/Detect-It-Easy/discussions)
-   **GitHub Issues**: Report bugs or request features via [Issues](https://github.com/horsicq/Detect-It-Easy/issues)

## 🏆 Special thanks

-   ⭐️ **Thanks to [DosX](https://github.com/DosX-dev)**

-   ⭐️ Thanks to [PELock](https://www.pelock.com)

## 🤝 Thanks to all contributors

<a href="https://github.com/horsicq/Detect-It-Easy/graphs/contributors">
<img src="https://readme-contribs.as93.net/contributors/horsicq/Detect-It-Easy?textColor=737373&perRow=9&shape=squircle&isResponsive=true" />
</a>

---

![Mascot](docs/logo2.png)

<!-- Dinosaur -->
<!--
                        . - ~ ~ ~ - .
      ..     _      .-~               ~-.
     //|     \ `..~                      `.
    || |      }  }              /       \  \
(\   \\ \~^..'                 |         }  \
 \`.-~  o      /       }       |        /    \
 (__          |       /        |       /      `.
  `- - ~ ~ -._|      /_ - ~ ~ ^|      /- _      `.
              |     /          |     /     ~-.     ~- _
              |_____|          |_____|         ~ - . _ _~_-_
(Grr-r-r!)
-->
