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
