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
