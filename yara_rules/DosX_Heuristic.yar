/*
    Author: DosX
    E-Mail: collab@kay-software.ru
    GitHub: https://github.com/DosX-dev
    Telegram: @DosX_dev
*/

import "pe"
import "math"

rule Obfuscated__AntiILDASM {
    strings:
        $suppressIldasm = "SuppressIldasmAttribute"
    condition:
        any of them
}

rule Obfuscated__FakeSignatures {
    strings:
        $_1 = "Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode"
        $_2 = "CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute"
        $_3 = "SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute"
        $_4 = "Xenocode.Client.Attributes.AssemblyAttributes"
        $_5 = "SmartAssembly.Attributes.PoweredByAttribute"
        $_6 = "ObfuscatedByAgileDotNetAttribute"
        $_7 = "NineRays.Obfuscator.Evaluation"
        $_8 = "ObfuscatedByCliSecureAttribute"
        $_9 = "BabelObfuscatorAttribute"
        $_10 = "AsStrongAsFuckAttribute"
        $_11 = "Macrobject.Obfuscator"
        $_12 = "DotfuscatorAttribute"
        $_13 = "CodeWallTrialVersion"
        $_14 = "ConfusedByAttribute"
        $_15 = "ObfuscatedByGoliath"
        $_16 = "NETSpider.Attribute"
        $_17 = "NineRays.Obfuscator"
        $_18 = "PoweredByAttribute"
        $_19 = "RustemSoft.Skater"
        $_20 = "BabelAttribute"
        $_21 = "YanoAttribute"
        $_22 = "EMyPID_8234_"
        $_23 = "ZYXDNGuarder"
        $_24 = "Sixxpack"
        $_25 = "____KILL"
        $_26 = "Reactor"
    condition:
        2 of them
}

rule Obfuscated__Virtualization {
    strings:
        $SystemReflection = "System.Reflection"
        $GetILGenerator = "GetILGenerator"
        $BeginInvoke = "BeginInvoke"
        $EndInvoke = "EndInvoke"
        $OpCode = "OpCode"
        $Ldarg_0 = "Ldarg_0"
        $CreateDelegate = "CreateDelegate"
    condition:
        ($SystemReflection and $GetILGenerator and $BeginInvoke and $EndInvoke and $OpCode) and ($Ldarg_0 or $CreateDelegate)
}

rule Obfuscated__AntiDe4dot {
    strings:
        $moduleName = "Form0"
    condition:
        any of them
}

rule Packed__EntryPoint {
    strings:
        $pushal = { 60 }
    condition:
        $pushal at entrypoint
}

rule Packed__HighEntropy {
    condition:
        uint32(uint32(0x3C)) == 0x00004550 and
		math.entropy(0, filesize) >= 7.0
}

rule Packed__AssemblyInvoke {
    strings:
        $SystemReflection = "System.Reflection"
        $get_EP = "get_EntryPoint"
        $Assembly = "Assembly"
        $Invoke = "Invoke"
        $Load = "Load"
    condition:
        all of them
}

rule AntiAnalysis__AntiSandboxie {
    strings:
        $winApi = "GetModuleHandle"
        $dllName = "sbiedll" wide nocase
    condition:
        $winApi and $dllName
}

rule AntiAnalysis__AntiDnSpy {
    strings:
        $dnName = "dnspy" wide nocase
    condition:
        any of them
}

rule AntiAnalysis__AntiVM {
    strings:
        $vmware = "vmware" wide nocase
        $virtualbox = "virtualbox" wide nocase
    condition:
        any of them
}

rule AntiAnalysis__AntiDebug {
    strings:
        $obj = "Debugger"
        $isAttached = "get_IsAttached"
        $isLogging = "IsLogging"
    condition:
        $obj and ($isAttached or $isLogging)
}
