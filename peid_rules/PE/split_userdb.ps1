$ErrorActionPreference = 'Stop'
$base = "C:\tmp_build\qt5\_mylibs\XPEID\peid\PE"
$content = Get-Content "$base\userdb.txt" -Raw -Encoding UTF8

# Category patterns (order matters - first match wins)
$categories = [ordered]@{
    'compiler' = '(?i)(Borland|Delphi|Visual\s+(C|Basic|Studio)|MSVC|\.NET|GCC|MinGW|Watcom|FASM|MASM|NASM|TASM|GoLink|LCC\s+Win|PureBasic|PowerBasic|FreeBasic|Turbo\s+(C|Pascal|Assembler|Basic)|Intel\s+C|Digital\s+Mars|Lahey|Dev-C|Code\s*Gear|Embarcadero|AutoIt|AutoHotkey|Lazarus|Free\s*Pascal|GNU\s+(C|Pascal)|Cygwin|DJGPP|Open\s*Watcom|Pelles\s+C|Tiny\s+C|lcc-win|Clarion|Eiffel|Ada\b|GNAT\b|CodeWarrior|Metrowerks|Symantec\s+C|Zortech|Power\s*C|Quick\s*C|Quick\s*Basic|Clipper|Harbour|C\+\+Builder|RAD\s*Studio|\.NET\s+(DLL|executable)|PE-Exe\s+Executable|BobSoft\s+Mini\s+Delphi|Microsoft\s+Visual|RSRC\b|Resource\s+Editor|Gentee|HiPEC|BlitzBasic|CAD-UL|PowerBASIC)'
    'packer' = '(?i)(UPX\b|ASPack|FSG\b|PECompact|PeCompact|PEBundle|Petite|NsPack|MPRESS|Upack|WinUpack|MEW\s|Neolite|PKLite|LZEXE|Diet\b|Crunch|KByS|nPack\b|PE.?Pack|JDPack|WWPack|Exe32Pack|AHPack|BeRo\s+EXE|kkrunchy|RLPack|PackMan|!EP\b|EPack\b|ExePack\b|Pack\s*Master|PEPACK|32Lite|PE\s+Intro|PE\s+Spin|PESpin|PEX\b|Packer\b|Dropper|Aspack|pack(?:ed|er|ing)|compress|SFX\b|WinZip|WinRAR|self.extract|7.Zip.*SFX|RAR\s+SFX|\$pirit|\$PIRIT|Special\s+EXE|SPLayer|SLVc0de\s+Joiner|PC\s+Shrinker|NorthStar|NoodleCrypt|Nullsoft\s+PiMP|PE\s+Diminisher|PEQuake|PENightMare|Vx\b)'
    'protector' = '(?i)(Armadillo|ExeCryptor|ASProtect|StarForce|SecuROM|SafeDisc|SafeNet|Sentinel|CodeVirtualizer|WinLicense|ACProtect|AntiCrack|ZProtect|PCGuard|SoftDefender|CopyMinder|PE.?Protect|PE.?SHiELD|PE.?Guard|PE.?Armor|PE.?Lock|PE.?Crypt|tElock|Themida|VMProtect|Enigma|Obsidium|MoleBox|Yoda.s\s+(Protector|Crypter)|Crypto|Crypt(?:er|or)\b|Cipher|Obfuscat|Morph(?:ine|er|ing)|SVK.Protector|DNGuard|Stealth|Anti.?Debug|NTkrnl|Xtreme.Protector|VProtector|ActiveMARK|VOB\s+Protect|Software\s+Passport|SoftSentry|CodeLock|PseudoSigner|EP\s+Protector|AHTeam|Hide.?PE|ORiEN|ProtectPE|SecureEXE|Stone.s\s+PE|WaterMark|EmbedPE|HASP\b|Dongle|Scrambl|NoobyProtect|PEStubOEP|Protect\b|Shield\b|Guard\b|Armor\b|Encr[iy]pt|Anti.?Tamper|License|Virtual(?:ize|Machine)|Code.?Virtual|Polymorph|CRC.Protect|ABC\s+Crypt|Acid\s*Crypt|WWCryptor|PCrypt|XCR\b|Krypton|Polycrypt|ReCrypt|SimplePack|The\s+Wall|Super\s+Protect|SProtect)'
    'joiner' = '(?i)(join|bind|binder|glue|merge|fuse|juntador|Exejoin|ExeBind|FileBinder|YAB\b)'
    'installer' = '(?i)(install|setup\b|deploy|wizard|InnoSetup|Inno\s+Install|NSIS|Nullsoft\s+Install|Wise|Ghost\s+Install|CreateInstall|Smart\s*Install|SetupFactory|InstallAnywhere|InstallJammer|BitRock|Advanced\s+Installer|GP.Install|Installer\s+VISE|Patch\s+Creation)'
    'sfx_archive' = '(?i)(Archive|\.cab\b|ZIP\s|GZIP|BZIP|\.rar\b|\.7z\b|\.ace\b|ARJ\b|LHA\b|LZH\b|ZOO\b|ARC\b\s|PKZip|PKSFX|ACE\s|AMGC|DWC\b|EZIP|FIZ\b|FOXSQZ|HA\s+Archive|HAP\b|HPack|Hyper\b|JAR\b|LIMIT\b|LZOP|PAK\b|QUANTUM|RAR\b|Reduce|SQZ\b|YAC\b|UC2\b|UHARC)'
    'file_format' = '(?i)(Graphics?\s+format|Audio\s+(file|format)|Image\s+file|Video\s+file|Font\s+file|Database\s+file|PDF|BMP\s+graph|GIF\s+graph|JPEG|PNG\s+graph|TIFF|WAV\b|MP3\b|MIDI|PCX\b|TGA\b|EPS\b|WMF\b|EMF\b|PIX\b|IFF\b|PSD\b|CDR\b|DXF\b|Kodak|Lotus|WordPerfect|PostScript|3DMark|Amiga|Alias\s+PIX|Alpha\s+BMP|Autodesk|ADEX|Adlib|Adobe|CorelDRAW|Rich\s+Text|DBase|FoxPro|Paradox|Excel|Access\s+Database|Executable\s+Image|Object\s+Module|AVI\b|RIFF\b|SWF\b|FLV\b|MOV\b|Atari|Macintosh|Apple|OS.2)'
    'overlay' = '(?i)(overlay|appended\s+data|Crinkler|Go32Stub|DOS.Extender|stub\s+engine)'
}

# Split content into blocks
$blocks = $content -split '(?m)(?=^\[)' | Where-Object { $_.Trim() -ne '' -and $_.Trim() -match '^\[' }

$results = @{}
foreach ($cat in $categories.Keys) {
    $results[$cat] = [System.Collections.Generic.List[string]]::new()
}
$results['protection'] = [System.Collections.Generic.List[string]]::new()

foreach ($block in $blocks) {
    $firstLine = ($block -split "`n")[0].Trim()
    $matched = $false
    foreach ($cat in $categories.Keys) {
        if ($firstLine -match $categories[$cat]) {
            $results[$cat].Add($block.TrimEnd())
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        $results['protection'].Add($block.TrimEnd())
    }
}

# Write files
$total = 0
foreach ($cat in $results.Keys | Sort-Object) {
    $count = $results[$cat].Count
    $total += $count
    $header = "; PEiD signature database - $cat`r`n; Auto-categorized from userdb.txt ($count entries)`r`n`r`n"
    Set-Content -Path "$base\$cat.userdb.txt" -Value ($header + ($results[$cat] -join "`r`n`r`n") + "`r`n") -Encoding UTF8
    Write-Output "$cat.userdb.txt: $count entries"
}

Write-Output ""
Write-Output "Total: $total (original: 4445)"
Write-Output ""
Write-Output "Files:"
Get-ChildItem "$base\*.userdb.txt" | Sort-Object Name | ForEach-Object { Write-Output "  $($_.Name) ($([math]::Round($_.Length/1024, 1)) KB)" }
