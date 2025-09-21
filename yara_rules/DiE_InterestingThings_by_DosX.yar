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

// Is PE?
private rule IsPE { condition: pe.is_pe }

// Is i386?
private rule Is32 { condition: pe.machine == 0x14c }

// Is Dynamic Link Library?
private rule IsDll { condition: pe.characteristics & 0x2000 != 0 }

// Is unmanaged/native?
private rule IsNative { condition: pe.data_directories[14].virtual_address == 0 }

// Is Rich signature present?
private rule IsRichSignPresent {
    strings: $rich_pe = { 52 69 63 68 [4-128] 50 45 00 00 } // 'Rich' ... 'PE\0\0'
    condition: for any i in (0x40..0x400) : (@rich_pe == i)
}

rule Compiler__NET_Native__debug {
    condition:
        IsPE and
        IsNative and
        IsRichSignPresent and
        pe.exports("DotNetRuntimeDebugHeader")
}

rule Compiler__NET_Native__release {
    strings:
        $exc_text = "Fatal error. Invalid Program: attempted to call a UnmanagedCallersOnly method from managed code."
    condition:
        IsPE and
        IsNative and
        IsRichSignPresent and
        not Compiler__NET_Native__debug and
        $exc_text in (0x40000..(pe.size_of_image - 0x8000))
}

rule Library__Qt_Framework {
    strings:
        $core_module_name = "QtCore"
        $qstring = "QString"
    condition:
        IsPE and
        IsNative and
        $core_module_name and $qstring
}

rule Packer__UPX {
    strings: $magicVerId = "UPX!"
    condition:
        IsPE and (
            pe.sections[0].name == "UPX0" and
            pe.sections[1].name == "UPX1"
        ) or $magicVerId in (0x40..0x400)
}

rule Packer__MPRESS {
    strings:
        $pushad = { 60 }
        $pushedi = { 57 }
        $magicForNative = { 57 69 6e ?? ?? 20 2e}
        $magicForDotNet = "It's .NET EXE"
    condition:
        IsPE and (
            pe.sections[0].name == ".MPRESS1" or (
                (IsNative and $magicForNative in (0x40..0x400)) or
                (not IsNative and $magicForDotNet in (0x40..0x400))
            )
        ) and (
            not IsNative or (
                $pushad at pe.entry_point or
                $pushedi at pe.entry_point
            )
        )
}

rule Packer__VPacker {
    strings:
        $entry = { 60 E8 ?? ?? ?? ?? C3 90 01 00 00 00 2C ?? 00 00 70 ?? 00 00 25 }
    condition:
        IsPE and
        IsNative and
        $entry at pe.entry_point
}

rule Packer__XPack {
    condition:
        IsPE and
        IsNative and
        pe.sections[0].name == ".XPack0"
}

rule Protection__obfus_h {
    condition:
        IsPE and
        IsNative and
        not IsRichSignPresent and (
            for any i in (0..pe.number_of_sections - 1) : (
                pe.sections[i].name == ".obfh"
            ) or pe.exports("WhatSoundDoesACowMake")
        )
}