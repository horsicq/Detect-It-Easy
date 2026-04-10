/*
    Author: DosX
    E-Mail: collab@kay-software.ru
    GitHub: https://github.com/DosX-dev
    Telegram: @DosX_dev
*/

// This module was written specifically for the Detect It Easy project.
// Please retain the copyright information when distributing it.

import "pe"
import "math"

// ============================================================================
//  Base private rules (reusable predicates)
// ============================================================================

private rule IsPE {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

private rule IsNative {
    condition:
        IsPE and pe.data_directories[14].virtual_address == 0
}

private rule Is64 {
    condition:
        IsPE and pe.machine == 0x8664
}

// ============================================================================
//  PE Header anomalies
// ============================================================================

rule Anomaly__ZeroSizedOptionalHeader {
    // OptionalHeader size must be non-zero for any real PE
    condition:
        IsPE and pe.size_of_optional_header == 0
}

rule Anomaly__SuspiciousImageBase {
    // Standard bases: 0x00400000 (EXE), 0x10000000 (DLL), 0x00010000 (CE).
    // Anything else is unusual and may indicate manual crafting or packing.
    condition:
        IsPE and
        IsNative and
        pe.image_base != 0x00400000 and
        pe.image_base != 0x10000000 and
        pe.image_base != 0x00010000 and
        pe.image_base != 0x01000000 and  // some Delphi/MSVC
        pe.image_base != 0x0000000140000000 and // x64 default
        pe.image_base % 0x10000 != 0  // must be 64K-aligned at minimum
}

rule Anomaly__ZeroEntryPoint {
    // EntryPoint == 0 is only valid for DLLs with no init code.
    // For executables it's an anomaly (packed/corrupt).
    condition:
        IsPE and
        pe.entry_point_raw == 0 and
        pe.characteristics & 0x2000 == 0  // not a DLL
}

rule Anomaly__EntryPointBeyondImage {
    // Entry point RVA exceeds SizeOfImage — broken or tampered header
    condition:
        IsPE and
        pe.entry_point >= pe.size_of_image
}

rule Anomaly__InvalidSectionAlignment {
    // SectionAlignment must be >= FileAlignment.
    // SectionAlignment < 0x200 is almost always hand-crafted.
    condition:
        IsPE and
        pe.section_alignment < pe.file_alignment
}

rule Anomaly__TinyFileAlignment {
    // FileAlignment below 0x200 (512) is legal for small alignment PEs,
    // but anything below 0x1 is invalid, and <0x200 is highly abnormal
    // for anything except special-purpose or packed binaries.
    condition:
        IsPE and (
            pe.file_alignment < 0x200 and
            pe.file_alignment != pe.section_alignment  // exclude valid same-alignment PEs
        )
}

rule Anomaly__ChecksumMismatch {
    // pe.checksum is the value from the header.
    // pe.calculate_checksum() is the actual computed one.
    // Mismatch = modified after linking or no checksum written.
    // Only flag when the header claims a non-zero checksum but it's wrong.
    condition:
        IsPE and
        pe.checksum != 0 and
        pe.checksum != pe.calculate_checksum()
}

rule Anomaly__ZeroSizeOfImage {
    condition:
        IsPE and pe.size_of_image == 0
}

rule Anomaly__LargeNumberOfSections {
    // Windows loader limits sections to 96 in practice.
    // >16 sections is already unusual; >40 is highly suspicious.
    condition:
        IsPE and pe.number_of_sections > 40
}

rule Anomaly__SuspiciousSubsystem {
    // Only WINDOWS_GUI (2), WINDOWS_CUI (3), NATIVE (1),
    // EFI_* (10-13) and WINDOWS_CE_GUI (9) are common.
    // Value 0 or >14 is almost certainly tampered.
    condition:
        IsPE and (
            pe.subsystem == 0 or pe.subsystem > 14
        )
}

rule Anomaly__DllCharacteristicsForcedIntegrity {
    // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080)
    // Extremely rare outside of kernel drivers and signed system components.
    condition:
        IsPE and
        pe.dll_characteristics & 0x0080 != 0 and
        pe.subsystem != 1  // not NATIVE (driver)
}

// ============================================================================
//  Section anomalies
// ============================================================================

rule Anomaly__WritableCodeSection {
    // A section that is both executable AND writable is a classic packer indicator.
    // .text should normally be RX, not RWX.
    condition:
        IsPE and
        IsNative and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].characteristics & 0x20000000 != 0 and  // MEM_EXECUTE
            pe.sections[i].characteristics & 0x80000000 != 0 and  // MEM_WRITE
            pe.sections[i].characteristics & 0x20 != 0            // CNT_CODE
        )
}

rule Anomaly__ExecutableDataSection {
    // .data, .rdata, .bss being executable is suspicious
    condition:
        IsPE and
        IsNative and
        for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].name == ".data" or
             pe.sections[i].name == ".rdata" or
             pe.sections[i].name == ".bss") and
            pe.sections[i].characteristics & 0x20000000 != 0  // MEM_EXECUTE
        )
}

rule Anomaly__SectionNameEmpty {
    // Sections without names are suspicious (packers strip section names)
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ""
        )
}

rule Anomaly__SectionNameNonPrintable {
    // Non-printable characters in section names indicate hand-crafting
    strings:
        $np = /[\x01-\x1f\x7f-\xff]{1}/ // at least one non-printable
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name matches /[^\x20-\x7e]/
        )
}

rule Anomaly__SectionZeroRawSize {
    // A section with zero raw size but non-zero virtual size
    // that also has executable permissions — shellcode/packer technique
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size == 0 and
            pe.sections[i].virtual_size > 0 and
            pe.sections[i].characteristics & 0x20000000 != 0  // MEM_EXECUTE
        )
}

rule Anomaly__SectionRawSizeExceedsFile {
    // Raw data extends beyond physical file — corrupt or tampered
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size > filesize and
            pe.sections[i].raw_data_size > 0
        )
}

rule Anomaly__SectionVirtualSizeMuchLarger {
    // VirtualSize >> RawDataSize (>10x) — unpacking stub pattern.
    // Excludes .bss (legitimately has zero raw, large virtual).
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0 and
            pe.sections[i].virtual_size > pe.sections[i].raw_data_size * 10 and
            pe.sections[i].name != ".bss"
        )
}

rule Anomaly__SectionHighEntropy {
    // Entropy > 7.2 for any section indicates compressed or encrypted data.
    // .rsrc can legitimately be high-entropy (PNG/JPEG), so we exclude it.
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name != ".rsrc" and
            pe.sections[i].raw_data_size > 256 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
        )
}

rule Anomaly__DuplicateSectionNames {
    // Two or more sections sharing the same name — hand-crafted PE
    condition:
        IsPE and
        pe.number_of_sections >= 2 and
        for any i in (0..pe.number_of_sections - 2) : (
            for any j in (i + 1..pe.number_of_sections - 1) : (
                pe.sections[i].name == pe.sections[j].name and
                pe.sections[i].name != ""
            )
        )
}

// ============================================================================
//  Entry point anomalies
// ============================================================================

rule Anomaly__EntryPointInLastSection {
    // EP in the last section is a classic indicator of appended code/packing.
    // Legitimate binaries almost always have EP in the first code section.
    // NOTE: pe.entry_point is a raw file offset (not RVA) when scanning files,
    // so we compare with raw_data_offset/raw_data_size, not virtual_address/virtual_size.
    condition:
        IsPE and
        IsNative and
        pe.number_of_sections >= 2 and
        pe.sections[pe.number_of_sections - 1].raw_data_size > 0 and
        pe.entry_point >= pe.sections[pe.number_of_sections - 1].raw_data_offset and
        pe.entry_point < pe.sections[pe.number_of_sections - 1].raw_data_offset +
                         pe.sections[pe.number_of_sections - 1].raw_data_size
}

rule Anomaly__EntryPointInNonCodeSection {
    // EP within a section that lacks the CODE flag.
    // Uses raw file offsets — pe.entry_point is a file offset, not RVA.
    condition:
        IsPE and
        IsNative and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0 and
            pe.entry_point >= pe.sections[i].raw_data_offset and
            pe.entry_point < pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size and
            pe.sections[i].characteristics & 0x20 == 0  // no CNT_CODE
        )
}

rule Anomaly__EntryPointOutsideAnySections {
    // EP doesn't fall within any defined section — header trick or packer stub.
    // Exclusions to prevent false positives:
    //   - EP == 0  → valid for DLLs without DllMain (caught separately by Anomaly__ZeroEntryPoint for EXEs)
    //   - DLLs     → AddressOfEntryPoint == 0 is fully legitimate, skip entirely
    //   - sections with VirtualSize == 0 are skipped to avoid miscalculated boundaries
    // NOTE: pe.entry_point is a raw file offset; virtual_address is RVA — different spaces.
    // We check raw file offset ranges. Sections with no raw data (e.g. .bss) are skipped.
    condition:
        IsPE and
        IsNative and
        pe.characteristics & 0x2000 == 0 and  // not DLL
        pe.entry_point != 0 and
        pe.number_of_sections > 0 and
        not for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 0 and
            pe.entry_point >= pe.sections[i].raw_data_offset and
            pe.entry_point < pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
        )
}

rule Anomaly__EPStartsWithNops {
    // EP begins with a NOP sled (4+ NOPs) — shellcode/packer trick
    strings:
        $nopsled = { 90 90 90 90 }
    condition:
        IsPE and
        IsNative and
        $nopsled at pe.entry_point
}

rule Anomaly__EPStartsWithInt3 {
    // EP begins with INT 3 (0xCC) — debug trap or anti-debug trick
    strings:
        $int3 = { CC }
    condition:
        IsPE and
        IsNative and
        $int3 at pe.entry_point
}

// ============================================================================
//  Import anomalies
// ============================================================================

rule Anomaly__NoImports {
    // Native PE with zero imports — almost impossible for legit PE, typical packer trait.
    // Exclude DLLs (they can be pure export-only).
    condition:
        IsPE and
        IsNative and
        pe.characteristics & 0x2000 == 0 and  // not DLL
        pe.number_of_imports == 0
}

rule Anomaly__SingleImportDll {
    // Only one import DLL (usually kernel32) — packer manually resolves everything else
    condition:
        IsPE and
        IsNative and
        pe.characteristics & 0x2000 == 0 and
        pe.number_of_imports == 1
}

rule Anomaly__SuspiciousMinimalImports {
    // Only LoadLibrary + GetProcAddress imported — classic manual resolve setup.
    // Often seen in packed/crypted executables.
    strings:
        $loadlib  = "LoadLibraryA"
        $loadlibW = "LoadLibraryW"
        $getproc  = "GetProcAddress"
    condition:
        IsPE and
        IsNative and
        pe.number_of_imports <= 2 and
        ($loadlib or $loadlibW) and
        $getproc
}

// ============================================================================
//  Overlay / data appending anomalies
// ============================================================================

rule Anomaly__LargeOverlay {
    // Overlay is data appended after the last section's raw data.
    // A large overlay (>50% of file) often means embedded payloads.
    condition:
        IsPE and
        pe.number_of_sections > 0 and
        pe.overlay.offset > 0 and
        pe.overlay.size > filesize / 2
}

rule Anomaly__OverlayPresent {
    // Overlay presence alone isn't an anomaly, but it's of interest when
    // combined with high entropy (embedded encrypted/compressed data).
    condition:
        IsPE and
        pe.overlay.offset > 0 and
        pe.overlay.size > 1024 and
        math.entropy(pe.overlay.offset, pe.overlay.size) > 7.0
}

// ============================================================================
//  Timestamp anomalies
// ============================================================================

rule Anomaly__FutureTimestamp {
    // TimeDateStamp in the future (>2026) — likely forged
    condition:
        IsPE and
        pe.timestamp > 1767225600  // Jan 1, 2026 UTC
}

rule Anomaly__AncientTimestamp {
    // TimeDateStamp before 1990 — PE format didn't exist before ~1993.
    // Also catches zero timestamps (Jan 1, 1970).
    condition:
        IsPE and
        pe.timestamp < 631152000 and  // Jan 1, 1990 UTC
        pe.timestamp != 0
}

rule Anomaly__ZeroTimestamp {
    // Zero timestamp — intentionally stripped (privacy or evasion)
    condition:
        IsPE and
        pe.timestamp == 0
}

// ============================================================================
//  Data directory anomalies
// ============================================================================

rule Anomaly__TLSCallbackPresent {
    // TLS callbacks execute before the entry point — used for anti-debug/evasion.
    // Not inherently malicious, but uncommon in benign software.
    condition:
        IsPE and
        IsNative and
        pe.data_directories[9].virtual_address != 0 and  // IMAGE_DIRECTORY_ENTRY_TLS
        pe.data_directories[9].size > 0
}

rule Anomaly__DebugDirectoryStripped {
    // Native PE with Rich header but no debug directory — info was stripped
    strings:
        $rich = { 52 69 63 68 }  // "Rich"
    condition:
        IsPE and
        IsNative and
        $rich in (0x40..0x400) and
        pe.data_directories[6].virtual_address == 0  // IMAGE_DIRECTORY_ENTRY_DEBUG
}

rule Anomaly__CLRHeaderInNativePE {
    // .NET metadata directory (index 14) present but PE also imports
    // heavy native API — confused tooling or .NET loader with native stubs
    condition:
        IsPE and
        pe.data_directories[14].virtual_address != 0 and
        pe.number_of_imports > 5
}

// ============================================================================
//  Resource anomalies
// ============================================================================

rule Anomaly__ResourceHighEntropy {
    // High-entropy resource section often indicates encrypted payload.
    // Legitimate high-entropy resources: PNG, JPEG, compressed icons.
    // We look for suspiciously high entropy (>7.4) which exceeds even PNG.
    condition:
        IsPE and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".rsrc" and
            pe.sections[i].raw_data_size > 4096 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.4
        )
}

rule Anomaly__ResourceDominatedBinary {
    // Resources make up >90% of the file — possible embedded payload binary.
    // Legit cases: icon editors, resource-only DLLs.
    // We exclude DLLs to reduce false positives.
    condition:
        IsPE and
        pe.characteristics & 0x2000 == 0 and  // not DLL
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".rsrc" and
            pe.sections[i].raw_data_size > filesize * 9 / 10
        )
}

// ============================================================================
//  Structural / whole-file anomalies
// ============================================================================

rule Anomaly__TinyPE {
    // Legitimate PE minimum is typically >4KB. Under 1KB is deeply abnormal.
    condition:
        IsPE and filesize < 1024
}

rule Anomaly__DOSStubMissing {
    // PE offset (e_lfanew) points right after the DOS header with no stub.
    // Normal MSVC/MinGW binaries include the "This program cannot be run in DOS mode" stub.
    // Missing stub = hand-crafted or size-optimized PE.
    condition:
        IsPE and
        uint32(0x3C) < 0x50  // PE header at less than 80 bytes — no room for DOS stub
}

rule Anomaly__DOSStubCustom {
    // Standard DOS stub contains "This program cannot be run in DOS mode".
    // A different or missing message = custom tooling.
    strings:
        $std_stub = "This program cannot be run in DOS mode"
        $std_stub2 = "This program must be run under Win32"
    condition:
        IsPE and
        uint32(0x3C) >= 0x80 and  // there is space for a stub
        not $std_stub in (0..uint32(0x3C)) and
        not $std_stub2 in (0..uint32(0x3C))
}

rule Anomaly__SelfModifyingHeaders {
    // PE header in a writable section — allows runtime header modification
    condition:
        IsPE and
        pe.number_of_sections > 0 and
        pe.sections[0].virtual_address <= pe.entry_point and
        pe.sections[0].characteristics & 0x80000000 != 0 and  // MEM_WRITE
        pe.sections[0].virtual_address == 0x1000
}

rule Anomaly__WholeFileHighEntropy {
    // Overall file entropy >7.0 strongly suggests compression/encryption.
    // pe.is_pe already ensures valid structure.
    condition:
        IsPE and
        filesize > 4096 and
        math.entropy(0, filesize) > 7.0
}

rule Anomaly__VersionInfoMissing {
    // Native PE without any version info resource — common for packers,
    // less common for production software.
    condition:
        IsPE and
        IsNative and
        pe.characteristics & 0x2000 == 0 and  // not DLL
        pe.number_of_resources == 0
}

// ============================================================================
//  Signature / trust anomalies
// ============================================================================

rule Anomaly__AuthenticodeCorrupt {
    // Security directory is present (claims to be signed) but has
    // size smaller than minimal PKCS#7 structure (~8 bytes minimum header).
    condition:
        IsPE and
        pe.data_directories[4].virtual_address != 0 and
        pe.data_directories[4].size < 8
}

rule Anomaly__SecurityDirPointsBeyondFile {
    // Security dir offset + size exceeds actual file size — appended or corrupt
    condition:
        IsPE and
        pe.data_directories[4].virtual_address != 0 and
        pe.data_directories[4].virtual_address + pe.data_directories[4].size > filesize
}