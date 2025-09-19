/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers1
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 32:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers2
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 48:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers3
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 64:sized"
		date = "2016-07"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers4
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 128:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers5
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 256:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}

rule Prime_Constants_char {
	meta:
		author = "_pusher_"
		description = "List of primes [char]"
		date = "2016-07"
	strings:
		$c0 = { 03 05 07 0B 0D 11 13 17 1D 1F 25 29 2B 2F 35 3B 3D 43 47 49 4F 53 59 61 65 67 6B 6D 71 7F 83 89 8B 95 97 9D A3 A7 AD B3 B5 BF C1 C5 C7 D3 DF E3 E5 E9 EF F1 FB }
	condition:
		$c0
}

rule Prime_Constants_long {
	meta:
		author = "_pusher_"
		description = "List of primes [long]"
		date = "2016-07"
	strings:
		$c0 = { 03 00 00 00 05 00 00 00 07 00 00 00 0B 00 00 00 0D 00 00 00 11 00 00 00 13 00 00 00 17 00 00 00 1D 00 00 00 1F 00 00 00 25 00 00 00 29 00 00 00 2B 00 00 00 2F 00 00 00 35 00 00 00 3B 00 00 00 3D 00 00 00 43 00 00 00 47 00 00 00 49 00 00 00 4F 00 00 00 53 00 00 00 59 00 00 00 61 00 00 00 65 00 00 00 67 00 00 00 6B 00 00 00 6D 00 00 00 71 00 00 00 7F 00 00 00 83 00 00 00 89 00 00 00 8B 00 00 00 95 00 00 00 97 00 00 00 9D 00 00 00 A3 00 00 00 A7 00 00 00 AD 00 00 00 B3 00 00 00 B5 00 00 00 BF 00 00 00 C1 00 00 00 C5 00 00 00 C7 00 00 00 D3 00 00 00 DF 00 00 00 E3 00 00 00 E5 00 00 00 E9 00 00 00 EF 00 00 00 F1 00 00 00 FB 00 00 00 }
	condition:
		$c0
}


rule Advapi_Hash_API {
	meta:
		author = "_pusher_"
		description = "Looks for advapi API functions"
		date = "2016-07"
	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$CryptCreateHash = "CryptCreateHash" wide ascii
		$CryptHashData = "CryptHashData" wide ascii
		$CryptAcquireContext = "CryptAcquireContext" wide ascii
	condition:
		$advapi32 and ($CryptCreateHash and $CryptHashData and $CryptAcquireContext)
}

rule Crypt32_CryptBinaryToString_API {
	meta:
		author = "_pusher_"
		description = "Looks for crypt32 CryptBinaryToStringA function"
		date = "2016-08"
	strings:
		$crypt32 = "crypt32.dll" wide ascii nocase
		$CryptBinaryToStringA = "CryptBinaryToStringA" wide ascii
	condition:
		$crypt32 and ($CryptBinaryToStringA)
}

rule CRC32c_poly_Constant {
	meta:
		author = "_pusher_"
		description = "Look for CRC32c (Castagnoli) [poly]"
		date = "2016-08"
	strings:
		$c0 = { 783BF682 }
	condition:
		$c0
}

rule CRC32_poly_Constant {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 [poly]"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 2083B8ED }
	condition:
		$c0
}

rule CRC32_table {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 table"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
	condition:
		$c0
}

rule CRC32_table_lookup {
	meta:
		author = "_pusher_"
		description = "CRC32 table lookup"
		date = "2015-06"
		version = "0.1"
	strings:
		$c0 = { 8B 54 24 08 85 D2 7F 03 33 C0 C3 83 C8 FF 33 C9 85 D2 7E 29 56 8B 74 24 08 57 8D 9B 00 00 00 00 0F B6 3C 31 33 F8 81 E7 FF 00 00 00 C1 E8 08 33 04 BD ?? ?? ?? ?? 41 3B CA 7C E5 5F 5E F7 D0 C3 }
	condition:
		$c0
}

rule CRC32b_poly_Constant {
	meta:
		author = "_pusher_"
		description = "Look for CRC32b [poly]"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { B71DC104 }
	condition:
		$c0
}


rule CRC16_table {
	meta:
		author = "_pusher_"
		description = "Look for CRC16 table"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { 00 00 21 10 42 20 63 30 84 40 A5 50 C6 60 E7 70 08 81 29 91 4A A1 6B B1 8C C1 AD D1 CE E1 EF F1 31 12 10 02 73 32 52 22 B5 52 94 42 F7 72 D6 62 39 93 18 83 7B B3 5A A3 BD D3 9C C3 FF F3 DE E3 }
	condition:
		$c0
}


rule FlyUtilsCnDES_ECB_Encrypt {
	meta:
		author = "_pusher_"
		description = "Look for FlyUtils.CnDES Encrypt ECB function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B D9 89 55 F8 89 45 FC 8B 7D 08 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 80 7D 18 00 74 1A 0F B6 55 18 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 80 7D 1C 00 74 1A 0F B6 55 1C 8D 4D E8 8B 45 FC E8 ?? ?? ?? ?? 8B 55 E8 8D 45 FC E8 ?? ?? ?? ?? 85 DB 75 07 E8 ?? ?? ?? ?? 8B D8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 53 6A 00 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 8B 45 F4 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 }
	condition:
		$c0
}

rule FlyUtilsCnDES_ECB_Decrypt {
	meta:
		author = "_pusher_"
		description = "Look for FlyUtils.CnDES Decrypt ECB function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D E8 89 5D EC 8B F9 89 55 F8 89 45 FC 8B 5D 18 8B 75 20 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 84 DB 74 18 8B D3 8D 4D EC 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 EC 8D 45 F8 E8 ?? ?? ?? ?? 85 FF 75 07 E8 ?? ?? ?? ?? 8B F8 85 F6 75 07 E8 ?? ?? ?? ?? 8B F0 8B 4D FC B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 57 6A 00 33 C9 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F0 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 6A 00 6A 00 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 FF 75 14 FF 75 10 8B 45 0C 50 8B 4D F8 8B 55 F0 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 6A 00 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 08 8B 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB 12 E9 ?? ?? ?? ?? 8B 45 08 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F0 33 D2 89 55 F0 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule Elf_Hash {
	meta:
		author = "_pusher_"
		description = "Look for ElfHash"
		date = "2015-06"
		version = "0.3"
	strings:
		$c0 = { 53 56 33 C9 8B DA 4B 85 DB 7C 25 43 C1 E1 04 33 D2 8A 10 03 CA 8B D1 81 E2 00 00 00 F0 85 D2 74 07 8B F2 C1 EE 18 33 CE F7 D2 23 CA 40 4B 75 DC 8B C1 5E 5B C3 }
		$c1 = { 53 33 D2 85 C0 74 2B EB 23 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 D7 8B C2 5B C3 }
		$c2 = { 53 56 33 C9 8B D8 85 D2 76 23 C1 E1 04 33 C0 8A 03 03 C8 8B C1 25 00 00 00 F0 85 C0 74 07 8B F0 C1 EE 18 33 CE F7 D0 23 C8 43 4A 75 DD 8B C1 5E 5B C3 }
		$c3 = { 53 56 57 8B F2 8B D8 8B FB 53 E8 ?? ?? ?? ?? 6B C0 02 71 05 E8 ?? ?? ?? ?? 8B D7 33 C9 8B D8 83 EB 01 71 05 E8 ?? ?? ?? ?? 85 DB 7C 2C 43 C1 E1 04 0F B6 02 03 C8 71 05 E8 ?? ?? ?? ?? 83 C2 01 B8 00 00 00 F0 23 C1 85 C0 74 07 8B F8 C1 EF 18 33 CF F7 D0 23 C8 4B 75 D5 8B C1 99 F7 FE 8B C2 85 C0 7D 09 03 C6 71 05 E8 ?? ?? ?? ?? 5F 5E 5B C3 }
		$c4 = { 53 33 D2 EB 2C 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CE 8B C2 5B C3 }
		$c5 = { 89 C2 31 C0 85 D2 74 30 2B 42 FC 74 2B 89 C1 29 C2 31 C0 53 0F B6 1C 11 01 C3 8D 04 1B C1 EB 14 8D 04 C5 00 00 00 00 81 E3 00 0F 00 00 31 D8 83 C1 01 75 E0 C1 E8 04 5B C3 }
		$c6 = { 53 33 D2 85 C0 74 38 EB 30 8B D9 80 C3 BF 80 EB 1A 73 03 80 C1 20 C1 E2 04 81 E1 FF 00 00 00 03 D1 8B CA 81 E1 00 00 00 F0 85 C9 74 07 8B D9 C1 EB 18 33 D3 F7 D1 23 D1 40 8A 08 84 C9 75 CA 8B C2 5B C3 }
	condition:
		any of them
}

rule BLOWFISH_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for Blowfish constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }	
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
		6 of them
}

rule MD5_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for MD5 constants"
		date = "2014-01"
		version = "0.2"
	strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
		5 of them
}

rule MD5_API {
	meta:
		author = "_pusher_"
		description = "Looks for MD5 API"
		date = "2016-07"
	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$cryptdll = "cryptdll.dll" wide ascii nocase
		$MD5Init = "MD5Init" wide ascii
		$MD5Update = "MD5Update" wide ascii
		$MD5Final = "MD5Final" wide ascii
	condition:
		($advapi32 or $cryptdll) and ($MD5Init and $MD5Update and $MD5Final)
}

rule RC6_Constants {
	meta:
		author = "chort (@chort0)"
		description = "Look for RC6 magic constants in binary"
		reference = "https://twitter.com/mikko/status/417620511397400576"
		reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
		date = "2013-12"
		version = "0.2"
	strings:
		$c1 = { B7E15163 }
		$c2 = { 9E3779B9 }
		$c3 = { 6351E1B7 }
		$c4 = { B979379E }
	condition:
		2 of them
}

rule RIPEMD160_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for RIPEMD-160 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}

rule SHA1_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA1 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
		//added by _pusher_ 2016-07 - last round
		$c10 = { D6C162CA }
	condition:
		5 of them
}

rule SHA512_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA384/SHA512 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}

rule SHA2_BLAKE2_IVs {
	meta:
		author = "spelissier"
		description = "Look for SHA2/BLAKE2/Argon2 IVs"
		date = "2019-12"
		version = "0.1"
	strings:
		$c0 = { 67 E6 09 6A }
		$c1 = { 85 AE 67 BB }
		$c2 = { 72 F3 6E 3C }
		$c3 = { 3A F5 4F A5 }
		$c4 = { 7F 52 0E 51 }
		$c5 = { 8C 68 05 9B }
		$c6 = { AB D9 83 1F }
		$c7 = { 19 CD E0 5B }

	condition:
		all of them
}

rule TEAN {
	meta:
		author = "_pusher_"
		description = "Look for TEA Encryption"
		date = "2016-08"
	strings:
		$c0 = { 2037EFC6 }
	condition:
		$c0
}

rule WHIRLPOOL_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for WhirlPool constants"
		date = "2014-02"
		version = "0.1"
	strings:
		$c0 = { 18186018c07830d8 }
		$c1 = { d83078c018601818 }
		$c2 = { 23238c2305af4626 }
		$c3 = { 2646af05238c2323 }
	condition:
		2 of them
}

rule DarkEYEv3_Cryptor {
	meta:
		description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
		author = "Florian Roth"
		reference = "http://darkeyev3.blogspot.fi/"
		date = "2015-05-24"
		hash0 = "6b854b967397f7de0da2326bdd5d39e710e2bb12"
		hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
		hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
		hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
		hash4 = "a907a7b74a096f024efe57953c85464e87275ba3"
		hash5 = "b1c422155f76f992048377ee50c79fe164b22293"
		hash6 = "29f5322ce5e9147f09e0a86cc23a7c8dc88721b9"
		hash7 = "a0382d7c12895489cb37efef74c5f666ea750b05"
		hash8 = "f3d5b71b7aeeb6cc917d5bb67e2165cf8a2fbe61"
		score = 55
	strings:
		$s0 = "\\DarkEYEV3-" 
	condition:
		uint16(0) == 0x5a4d and $s0
}

rule Miracl_powmod
{	meta:
		author = "Maxx"
		description = "Miracl powmod"
	strings:
		$c0 = { 53 55 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 0F 85 EC 01 00 00 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 12 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 06 8B 4E 10 3B C1 74 2E 8B 7C 24 1C 57 E8 ?? ?? ?? ?? 83 C4 04 83 F8 02 7C 33 8B 57 04 8B 0E 51 8B 02 50 E8 ?? ?? ?? ?? 83 C4 08 83 F8 01 0F 84 58 01 00 00 EB 17 8B 7C 24 1C 6A 02 57 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 3F 01 00 00 8B 8E C4 01 00 00 8B 54 24 18 51 52 E8 ?? ?? ?? ?? 8B 86 CC }
	condition:
		$c0
}

rule Miracl_crt
{	meta:
		author = "Maxx"
		description = "Miracl crt"
	strings:
		$c0 = { 51 56 57 E8 ?? ?? ?? ?? 8B 74 24 10 8B F8 89 7C 24 08 83 7E 0C 02 0F 8C 99 01 00 00 8B 87 18 02 00 00 85 C0 0F 85 8B 01 00 00 8B 57 1C 42 8B C2 89 57 1C 83 F8 18 7D 17 C7 44 87 20 4A 00 00 00 8B 87 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 46 04 8B 54 24 14 53 55 8B 08 8B 02 51 50 E8 ?? ?? ?? ?? 8B 4E 0C B8 01 00 00 00 83 C4 08 33 ED 3B C8 89 44 24 18 0F 8E C5 00 00 00 BF 04 00 00 00 8B 46 04 8B 0C 07 8B 10 8B 44 24 1C 51 52 8B 0C 07 51 E8 ?? ?? ?? ?? 8B 56 04 8B 4E 08 8B 04 }
	condition:
		$c0
}

rule CryptoPP_a_exp_b_mod_c
{	meta:
		author = "Maxx"
		description = "CryptoPP a_exp_b_mod_c"
	strings:
		$c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC ?? 00 00 00 56 8B B4 24 B0 00 00 00 57 6A 00 8B CE C7 44 24 0C 00 00 00 00 E8 ?? ?? ?? ?? 84 C0 0F 85 16 01 00 00 8D 4C 24 24 E8 ?? ?? ?? ?? BF 01 00 00 00 56 8D 4C 24 34 89 BC 24 A4 00 00 00 E8 ?? ?? ?? ?? 8B 06 8D 4C 24 3C 50 6A 00 C6 84 24 A8 00 00 00 02 E8 ?? ?? ?? ?? 8D 4C 24 48 C6 84 24 A0 00 00 00 03 E8 ?? ?? ?? ?? C7 44 24 24 ?? ?? ?? ?? 8B 8C 24 AC 00 00 00 8D 54 24 0C 51 52 8D 4C 24 2C C7 84 24 A8 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 4C 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 70 8D 4C 24 18 56 89 7C 24 60 E8 ?? ?? ?? ?? 8B 76 08 8D 4C 24 2C 56 57 C6 44 24 64 01 E8 ?? ?? ?? ?? 8D 4C 24 40 C6 44 24 5C 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 4C 24 6C 8B 54 24 68 8B 74 24 64 51 52 56 8D 4C 24 18 C7 44 24 68 03 00 00 00 E8 ?? ?? ?? ?? 8B 7C 24 4C 8B 4C 24 48 8B D7 33 C0 F3 }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 34 56 57 33 FF 8D 44 24 0C 89 7C 24 08 C7 44 24 10 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 89 44 24 14 8B 74 24 58 8D 4C 24 18 56 89 7C 24 48 E8 ?? ?? ?? ?? 8B 0E C6 44 24 44 01 51 57 8D 4C 24 2C E8 ?? ?? ?? ?? 8D 4C 24 30 C6 44 24 44 02 E8 ?? ?? ?? ?? C7 44 24 0C ?? ?? ?? ?? 8B 54 24 54 8B 44 24 50 8B 74 24 4C 52 50 56 8D 4C 24 18 C7 44 24 50 03 00 00 00 E8 ?? ?? ?? ?? 8B 4C 24 30 8B 7C 24 34 33 C0 F3 AB 8B 4C }
	condition:
		any of them
}

rule CryptoPP_modulo
{	meta:
		author = "Maxx"
		description = "CryptoPP modulo"
	strings:
		$c0 = { 83 EC 20 53 55 8B 6C 24 2C 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 04 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 04 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 04 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 34 33 C9 53 0B CA 55 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 56 57 8B F1 33 FF 8D 4C 24 20 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 0C 89 7C 24 3C E8 ?? ?? ?? ?? 8B 44 24 48 8D 4C 24 0C 50 56 8D 54 24 28 51 52 C6 44 24 4C 01 E8 ?? ?? ?? ?? 8B 74 24 54 83 C4 10 8D 44 24 20 8B CE 50 E8 ?? ?? ?? ?? 8B 7C 24 18 8B 4C 24 14 8B D7 33 C0 F3 AB 52 E8 ?? ?? ?? ?? 8B 7C 24 30 8B 4C 24 2C 8B D7 33 C0 C7 44 24 10 ?? ?? ?? ?? 52 F3 AB E8 ?? ?? ?? ?? 8B 4C 24 3C 83 C4 08 8B C6 64 89 }
		$c2 = { 83 EC 24 53 55 8B 6C 24 30 8B D9 85 ED 89 5C 24 08 75 18 8D 4C 24 0C E8 ?? ?? ?? ?? 8D 44 24 0C 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 4D FF 56 85 CD 57 75 09 8B 53 0C 8B 02 23 C1 EB 76 8B CB E8 ?? ?? ?? ?? 83 FD 05 8B C8 77 2D 33 F6 33 FF 49 85 C0 74 18 8B 53 0C 8D 41 01 8D 14 8A 8B 0A 03 F1 83 D7 00 48 83 EA 04 85 C0 77 F1 6A 00 55 57 56 E8 ?? ?? ?? ?? EB 3B 33 C0 8B D1 49 85 D2 74 32 8B 54 24 10 33 DB 8D 71 01 8B 52 0C 8D 3C 8A 8B 17 33 ED 0B C5 8B 6C 24 38 33 C9 53 0B CA 55 }
		$c3 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 1C 56 57 8B F1 33 FF 8D 4C 24 0C 89 7C 24 08 E8 ?? ?? ?? ?? 8D 4C 24 18 89 7C 24 2C E8 ?? ?? ?? ?? 8B 44 24 38 8D 4C 24 18 50 56 8D 54 24 14 51 52 C6 44 24 3C 01 E8 ?? ?? ?? ?? 8B 74 24 44 83 C4 10 8D 44 24 0C 8B CE 50 E8 ?? ?? ?? ?? 8B 4C 24 18 8B 7C 24 1C 33 C0 F3 AB 8B 4C 24 1C 51 E8 ?? ?? ?? ?? 8B 4C 24 10 8B 7C 24 14 33 C0 F3 AB 8B 54 24 14 52 E8 ?? ?? ?? ?? 8B 4C 24 2C 83 C4 08 8B C6 64 89 0D 00 00 00 }
	condition:
		any of them
}

rule FGint_MontgomeryModExp
{	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint MontgomeryModExp"
	strings:
		$c0 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c1 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c2 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 ?? 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 ?? E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 }
		$c3 = { 55 8B EC 83 C4 ?? 53 56 57 33 DB 89 5D ?? 8B F1 8B DA 89 45 D0 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 47 4C 47 00 64 FF 30 64 89 20 8D 55 D4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CF 8B D6 8B 45 D0 E8 ?? ?? ?? ?? 8D 55 D4 8B C7 E8 ?? ?? ?? ?? 3C 02 75 0D 8D 45 D4 E8 ?? ?? ?? ?? E9 02 02 00 00 }
	condition:
		any of them
}

rule FGint_FGIntModExp
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntModExp"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 57 33 DB 89 5D ?? 8B F1 89 55 ?? 8B D8 8B 7D 08 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 46 04 8B 40 04 83 E0 01 83 F8 01 75 0F 57 8B CE 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? EB ?? 8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 F4 8B C3 E8 ?? ?? ?? ?? 8B 45 }
	condition:
		$c0
}

rule FGint_MulByInt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MulByInt"
	strings:
		$c0 = { 53 56 57 55 83 C4 E8 89 4C 24 04 8B EA 89 04 24 8B 04 24 8B 40 04 8B 00 89 44 24 08 8B 44 24 08 83 C0 02 50 8D 45 04 B9 01 00 00 00 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 04 33 F6 8B 7C 24 08 85 FF 76 6D BB 01 00 00 00 8B 04 24 8B 40 04 8B 04 98 33 D2 89 44 24 10 89 54 24 14 8B 44 24 04 33 D2 52 50 8B 44 24 18 8B 54 24 1C ?? ?? ?? ?? ?? 89 44 24 10 89 54 24 14 8B C6 33 D2 03 44 24 10 13 54 24 14 89 44 24 10 89 54 24 14 8B 44 24 10 25 FF FF FF 7F 8B 55 04 89 04 9A 8B 44 24 10 8B 54 24 14 0F AC D0 1F C1 EA 1F 8B F0 43 4F 75 98 }
	condition:
		$c0
}

rule FGint_DivMod
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDivMod"
	strings:
		$c0 = { 55 8B EC 83 C4 BC 53 56 57 8B F1 89 55 F8 89 45 FC 8B 5D 08 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 FC 8A 00 88 45 D7 8B 45 F8 8A 00 88 45 D6 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B D3 8B 45 FC E8 ?? ?? ?? ?? 8D 55 E0 8B 45 F8 E8 ?? ?? ?? ?? 8B 55 F8 8B 45 FC }
	condition:
		$c0
}

rule FGint_FGIntDestroy
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint FGIntDestroy"
	strings:
		$c0 = { 53 8B D8 8D 43 04 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$c0
}

rule FGint_Base10StringToGInt
{	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint Base10StringToGInt"
	strings:
		$c0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 8B DA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC ?? ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC ?? ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? EB 18 C6 45 EB 01 EB 12 8D 45 FC }
		$c1 = { 55 8B EC 83 C4 D8 53 56 57 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D E4 89 4D EC 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 0F 42 45 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 8A 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D4 8D 45 E4 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E4 BA 28 42 45 00 E8 ?? ?? ?? ?? 75 18 C6 45 EB 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 EB 01 }
		$c2 = { 55 8B EC 83 C4 D8 53 56 33 C9 89 4D D8 89 4D DC 89 4D E0 89 4D F8 89 4D F4 8B DA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 A6 32 47 00 64 FF 30 64 89 20 EB 12 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 8B 45 FC 0F B6 00 2C 2D 74 11 04 FD 2C 0A 72 0B 8B 45 FC E8 ?? ?? ?? ?? 48 7F D3 8D 45 E0 50 B9 01 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 45 E0 BA BC 32 47 00 E8 ?? ?? ?? ?? 75 18 C6 45 E9 00 8D 45 FC B9 01 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? EB 18 C6 45 E9 01 }

	condition:
		any of them
}

rule FGint_ConvertBase256to64
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256to64"
	strings:
		$c0 = { 55 8B EC 81 C4 EC FB FF FF 53 56 57 33 C9 89 8D EC FB FF FF 89 8D F0 FB FF FF 89 4D F8 8B FA 89 45 FC B9 00 01 00 00 8D 85 F4 FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 F4 FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 7E 2F BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F4 FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E5 EB }
	condition:
		$c0
}

rule FGint_ConvertHexStringToBase256String
{	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint ConvertHexStringToBase256String"
	strings:
		$c0 = { 55 8B EC 83 C4 F0 53 56 33 C9 89 4D F0 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? D1 F8 79 03 83 D0 00 85 C0 7E 5F 89 45 F4 BE 01 00 00 00 8B C6 03 C0 8B 55 FC 8A 54 02 FF 8B 4D FC 8A 44 01 FE 3C 3A 73 0A 8B D8 80 EB 30 C1 E3 04 EB 08 8B D8 80 EB 37 C1 E3 04 80 FA 3A 73 07 80 EA 30 0A DA EB 05 80 EA 37 0A DA 8D 45 F0 8B D3 }
	condition:
		$c0
}

rule FGint_Base256StringToGInt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint Base256StringToGInt"
	strings:
		$c0 = { 55 8B EC 81 C4 F8 FB FF FF 53 56 57 33 C9 89 4D F8 8B FA 89 45 FC 8B 45 FC ?? ?? ?? ?? ?? B9 00 01 00 00 8D 85 F8 FB FF FF 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F8 ?? ?? ?? ?? ?? 8D 85 F8 FB FF FF BA FF 00 00 00 ?? ?? ?? ?? ?? 8B 45 FC ?? ?? ?? ?? ?? 8B D8 85 DB 7E 34 BE 01 00 00 00 8D 45 F8 8B 55 FC 0F B6 54 32 FF 8B 94 95 F8 FB FF FF ?? ?? ?? ?? ?? 46 4B 75 E5 EB 12 8D 45 F8 B9 01 00 00 00 BA 01 00 00 00 ?? ?? ?? ?? ?? 8B 45 F8 80 38 30 75 0F }
	condition:
		$c0
}

rule FGint_FGIntToBase256String
{	meta:
		author = "_pusher_"
		date = "2015-06"
		version = "0.2"
		description = "FGint FGIntToBase256String"
	strings:
		$c0 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC E8 ?? ?? ?? ?? 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4B 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 8A 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 ?? ?? ?? ?? 4B 75 B5 }
		$c1 = { 55 8B EC 33 C9 51 51 51 51 53 56 8B F2 33 D2 55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8D 55 FC E8 ?? ?? ?? ?? EB 10 8D 45 FC 8B 4D FC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 C8 F8 40 85 C0 75 D8 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 8B D8 85 DB 79 03 83 C3 07 C1 FB 03 8B C6 E8 ?? ?? ?? ?? 85 DB 76 4C 8D 45 F4 50 B9 08 00 00 00 BA 01 00 00 00 8B 45 FC E8 ?? ?? ?? ?? 8B 55 F4 8D 45 FB E8 ?? ?? ?? ?? 8D 45 F0 0F B6 55 FB E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8D 45 FC B9 08 00 00 00 BA 01 00 00 00 E8 }
	condition:
		any of them
}

rule FGint_ConvertBase256StringToHexString
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint ConvertBase256StringToHexString"
	strings:
		$c0 = { 55 8B EC 33 C9 51 51 51 51 51 51 53 56 57 8B F2 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C6 E8 ?? ?? ?? ?? 8B 45 FC E8 ?? ?? ?? ?? 8B F8 85 FF 0F 8E AB 00 00 00 C7 45 F8 01 00 00 00 8B 45 FC 8B 55 F8 8A 5C 10 FF 33 C0 8A C3 C1 E8 04 83 F8 0A 73 1E 8D 45 F4 33 D2 8A D3 C1 EA 04 83 C2 30 E8 ?? ?? ?? ?? 8B 55 F4 8B C6 E8 ?? ?? ?? ?? EB 1C 8D 45 F0 33 D2 8A D3 C1 EA 04 83 C2 37 E8 ?? ?? ?? ?? 8B 55 F0 8B C6 E8 ?? ?? ?? ?? 8B C3 24 0F 3C 0A 73 22 8D 45 EC 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 30 E8 ?? ?? ?? ?? 8B 55 EC 8B C6 E8 ?? ?? ?? ?? EB 20 8D 45 E8 8B D3 80 E2 0F 81 E2 FF 00 00 00 83 C2 37 }
	condition:
		$c0
}


rule FGint_PGPConvertBase256to64
{	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint PGPConvertBase256to64"
	strings:
		$c0 = { 55 8B EC 81 C4 E8 FB FF FF 53 56 57 33 C9 89 8D E8 FB FF FF 89 4D F8 89 4D F4 89 4D F0 8B FA 89 45 FC B9 00 01 00 00 8D 85 EC FB FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 EC FB FF FF BA FF 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 E8 ?? ?? ?? ?? 8B 45 FC 8B 00 E8 ?? ?? ?? ?? 8B D8 85 DB 7E 22 BE 01 00 00 00 8D 45 F8 8B 55 FC 8B 12 0F B6 54 32 FF 8B 94 95 EC FB FF FF E8 ?? ?? ?? ?? 46 4B 75 E3 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 85 D2 75 0A 8D 45 F0 E8 ?? ?? ?? ?? EB 4B 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 83 FA 04 75 1C 8D 45 F8 BA 4C 33 40 00 E8 ?? ?? ?? ?? 8D 45 F0 BA 58 33 40 00 E8 ?? ?? ?? ?? EB 1A 8D 45 F8 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? B9 06 00 00 00 99 F7 F9 8B D8 85 DB 7E 57 8D 45 F4 50 B9 06 00 00 00 BA 01 00 00 00 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 EC 8B 55 F4 E8 ?? ?? ?? ?? 8D 85 E8 FB FF FF 8B 55 EC 8A 92 ?? ?? ?? ?? E8 }
	condition:
		$c0
}


rule FGint_RSAEncrypt
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint RSAEncrypt"
	strings:
		$c0 = { 55 8B EC 83 C4 D0 53 56 57 33 DB 89 5D D0 89 5D DC 89 5D D8 89 5D D4 8B F9 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 DC 8B C7 E8 ?? ?? ?? ?? 8B 45 DC E8 ?? ?? ?? ?? 8B D8 8D 55 DC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 DC 8B 4D DC BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F3 4E EB 10 }
	condition:
		$c0
}

rule FGint_RsaDecrypt
{	meta:
		author = "Maxx"
		description = "FGint RsaDecrypt"
	strings:
		$c0 = { 55 8B EC 83 C4 A0 53 56 57 33 DB 89 5D A0 89 5D A4 89 5D A8 89 5D B4 89 5D B0 89 5D AC 89 4D F8 8B FA 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 }
	condition:
		$c0
}

rule FGint_RSAVerify
{	meta:
		author = "_pusher_"
		description = "FGint RSAVerify"
	strings:
		$c0 = { 55 8B EC 83 C4 E0 53 56 8B F1 89 55 F8 89 45 FC 8B 5D 0C 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 E8 8B 45 F8 E8 ?? ?? ?? ?? 8D 55 F0 8B 45 FC E8 ?? ?? ?? ?? 8D 4D E0 8B D3 8D 45 F0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 50 8B CB 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8D 55 F0 8D 45 E8 E8 ?? ?? ?? ?? 3C 02 8B 45 08 0F 94 00 8D 45 E8 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 03 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 BA 02 00 00 00 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule FGint_FindPrimeGoodCurveAndPoint
{	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint FindPrimeGoodCurveAndPoint"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 F4 53 56 57 33 DB 89 5D F4 89 4D FC 8B FA 8B F0 33 C0 55 }
	condition:
		$c0
}

rule FGint_ECElGamalEncrypt
{	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint ECElGamalEncrypt"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 81 C4 3C FF FF FF 53 56 57 33 DB 89 5D D8 89 5D D4 89 5D D0 8B 75 10 8D 7D 8C A5 A5 A5 A5 A5 8B 75 14 8D 7D A0 A5 A5 A5 A5 A5 8B 75 18 8D 7D DC A5 A5 8B 75 1C 8D 7D E4 A5 A5 8B F1 8D 7D EC A5 A5 8B F2 8D 7D F4 A5 A5 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 8C 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 78 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 64 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 50 FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 3C FF FF FF 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 7D CF }
		$c1 = { 55 8B EC 83 C4 A8 53 56 57 33 DB 89 5D A8 89 5D AC 89 5D BC 89 5D B8 89 5D B4 89 4D F4 89 55 F8 89 45 FC 8B 75 0C 8B 45 FC E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 71 14 41 00 64 FF 30 64 89 20 8D 55 BC 8B C6 E8 ?? ?? ?? ?? 8B 45 BC E8 ?? ?? ?? ?? 8B D8 8D 55 BC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 8B 4D BC BA 8C 14 41 00 E8 ?? ?? ?? ?? 8B FB 4F EB 10 8D 45 BC 8B 4D BC BA 98 14 41 00 E8 ?? ?? ?? ?? 8B 45 BC }
	condition:
		$c0 or $c1
}

rule FGint_ECAddPoints
{	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECAddPoints"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 A8 53 56 57 8B 75 0C 8D 7D F0 A5 A5 8B F1 8D 7D F8 A5 A5 8B F2 8D 7D A8 A5 A5 A5 A5 A5 8B F0 8D 7D BC A5 A5 A5 A5 A5 8B 5D 08 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 }
	condition:
		$c0
}

rule FGint_ECPointKMultiple
{	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECPointKMultiple"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 BC 53 56 57 33 DB 89 5D E4 8B 75 0C 8D 7D E8 A5 A5 8B F1 8D 7D F0 A5 A5 8B F2 8D 7D F8 A5 A5 8B F0 8D 7D D0 A5 A5 A5 A5 A5 8B 5D 08 8D 45 D0 8B 15 ?? ?? ?? 00 E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 }
	condition:
		$c0
}

rule FGint_ECPointDestroy
{	meta:
		author = "_pusher_"
		date = "2015-06"
		description = "FGint ECPointDestroy"
		version = "0.1"
	strings:
		$c0 = { 53 8B D8 8B C3 E8 ?? ?? ?? ?? 8D 43 08 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$c0
}

rule FGint_DSAPrimeSearch
{	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSAPrimeSearch"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 DC 53 56 8B DA 8B F0 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 4D F8 8B D6 8B C6 E8 ?? ?? ?? ?? 8D 4D E8 8B D6 8B C3 E8 ?? ?? ?? ?? 8D 55 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D E0 8D 55 E8 8B C3 E8 ?? ?? ?? ?? 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D E8 8D 55 F0 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 E0 E8 ?? ?? ?? ?? 8D 45 F0 E8 ?? ?? ?? ?? 8B 45 EC 8B 40 04 83 E0 01 85 C0 75 18 8D 4D E0 8B D6 8D 45 E8 E8 ?? ?? ?? ?? 8D 55 E8 8D 45 E0 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? C6 45 DF 00 EB 26 8D 4D E8 8D 55 F8 8B C3 E8 ?? ?? ?? ?? 8B D3 8D 45 E8 E8 ?? ?? ?? ?? 8D 4D DF 8B C3 BA 05 00 00 00 E8 ?? ?? ?? ?? 80 7D DF 00 74 D4 8D 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? B9 04 00 00 00 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule FGint_DSASign
{	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSASign"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 CC 53 56 57 89 4D FC 8B DA 8B F8 8B 75 14 8B 45 10 E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 F4 50 8B CF 8B D6 8B 45 FC E8 ?? ?? ?? ?? 8D 4D D4 8B D3 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8B C6 E8 ?? ?? ?? ?? 8D 55 EC 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 D4 8B 45 18 E8 ?? ?? ?? ?? 8D 4D DC 8D 55 E4 8D 45 EC E8 ?? ?? ?? ?? 8D 45 EC E8 ?? ?? ?? ?? 8D 45 E4 E8 ?? ?? ?? ?? 8D 45 CC 50 8B CB 8D 55 DC 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 DC E8 ?? ?? ?? ?? 8B 55 0C 8D 45 D4 E8 ?? ?? ?? ?? 8B 55 08 8D 45 CC E8 ?? ?? ?? ?? 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 CC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? B9 06 00 00 00 E8 }
	condition:
		$c0
}

rule FGint_DSAVerify
{	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "FGint DSAVerify"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 B4 53 56 57 89 4D FC 8B DA 8B F0 8B 7D 08 8B 45 14 E8 ?? ?? ?? ?? 8B 45 10 E8 ?? ?? ?? ?? 8B 45 0C E8 ?? ?? ?? ?? 8D 45 F4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 EC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 DC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 CC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B4 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 CC 8B 45 0C E8 ?? ?? ?? ?? 8D 4D F4 8B D3 8D 45 CC E8 ?? ?? ?? ?? 8D 55 C4 8B 45 14 E8 ?? ?? ?? ?? 8D 45 EC 50 8B CB 8D 55 F4 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 ?? ?? ?? ?? 8D 55 D4 8B 45 10 E8 ?? ?? ?? ?? 8D 45 E4 50 8B CB 8D 55 F4 8D 45 D4 E8 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? 8D 45 C4 50 8B CE 8D 55 EC 8B 45 FC E8 ?? ?? ?? ?? 8D 45 BC 50 8B CE 8D 55 E4 8B 45 18 E8 ?? ?? ?? ?? 8D 45 B4 50 8B CE 8D 55 BC 8D 45 C4 E8 ?? ?? ?? ?? 8D 45 C4 E8 }
	condition:
		$c0
}


rule DES_Long
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [long]"
	strings:
		$c0 = { 10 80 10 40 00 00 00 00 00 80 10 00 00 00 10 40 10 00 00 40 10 80 00 00 00 80 00 40 00 80 10 00 00 80 00 00 10 00 10 40 10 00 00 00 00 80 00 40 10 00 10 00 00 80 10 40 00 00 10 40 10 00 00 00 }
	condition:
		$c0
}

rule DES_sbox
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [sbox]"
	strings:
		$c0 = { 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 }
	condition:
		$c0
}

rule DES_pbox_long
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [pbox] [long]"
	strings:
		$c0 = { 0F 00 00 00 06 00 00 00 13 00 00 00 14 00 00 00 1C 00 00 00 0B 00 00 00 1B 00 00 00 10 00 00 00 00 00 00 00 0E 00 00 00 16 00 00 00 19 00 00 00 04 00 00 00 11 00 00 00 1E 00 00 00 09 00 00 00 01 00 00 00 07 00 00 00 17 00 00 00 0D 00 00 00 1F 00 00 00 1A 00 00 00 02 00 00 00 08 00 00 00 12 00 00 00 0C 00 00 00 1D 00 00 00 05 00 00 00 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp2_mont
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp2_mont"
	strings:
		$c0 = { B8 30 05 00 00 E8 ?? ?? ?? ?? 8B 84 24 48 05 00 00 53 33 DB 56 8B 08 57 89 5C 24 24 89 5C 24 30 8A 01 89 5C 24 28 A8 01 89 5C 24 0C 75 24 68 89 00 00 00 68 ?? ?? ?? ?? 6A 66 6A 76 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 30 05 00 00 C3 8B 94 24 48 05 00 00 52 E8 ?? ?? ?? ?? 8B F0 8B 84 24 54 05 00 00 50 E8 ?? ?? ?? ?? 83 C4 08 3B F3 8B F8 75 20 3B FB 75 1C 8B 8C 24 40 05 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 30 05 00 00 C3 3B F7 89 74 24 18 7F 04 89 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_mont
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_mont"
	strings:
		$c0 = { B8 A0 02 00 00 E8 ?? ?? ?? ?? 53 56 57 8B BC 24 BC 02 00 00 33 F6 8B 07 89 74 24 24 89 74 24 20 89 74 24 0C F6 00 01 75 24 68 72 01 00 00 68 ?? ?? ?? ?? 6A 66 6A 6D 6A 03 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 81 C4 A0 02 00 00 C3 8B 8C 24 B8 02 00 00 51 E8 ?? ?? ?? ?? 8B D8 83 C4 04 3B DE 89 5C 24 18 75 1C 8B 94 24 B0 02 00 00 6A 01 52 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5B 81 C4 A0 02 00 00 C3 55 8B AC 24 C4 02 00 00 55 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B F0 55 89 74 24 24 E8 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_recp
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_recp"
	strings:
		$c0 = { B8 C8 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 D4 02 00 00 55 56 33 F6 50 89 74 24 1C 89 74 24 18 E8 ?? ?? ?? ?? 8B E8 83 C4 04 3B EE 89 6C 24 0C 75 1B 8B 8C 24 D4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 C8 02 00 00 C3 53 57 8B BC 24 EC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DE 0F 84 E7 02 00 00 8D 54 24 24 52 E8 ?? ?? ?? ?? 8B B4 24 EC 02 00 00 83 C4 04 8B 46 0C 85 C0 74 32 56 53 E8 ?? ?? ?? ?? 83 C4 08 85 C0 0F 84 BA 02 00 00 57 8D 44 24 28 53 }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_simple
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_simple"
	strings:
		$c0 = { B8 98 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 A4 02 00 00 55 56 33 ED 50 89 6C 24 1C 89 6C 24 18 E8 ?? ?? ?? ?? 8B F0 83 C4 04 3B F5 89 74 24 0C 75 1B 8B 8C 24 A4 02 00 00 6A 01 51 E8 ?? ?? ?? ?? 83 C4 08 5E 5D 81 C4 98 02 00 00 C3 53 57 8B BC 24 BC 02 00 00 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B D8 83 C4 08 3B DD 0F 84 71 02 00 00 8D 54 24 28 52 E8 ?? ?? ?? ?? 8B AC 24 BC 02 00 00 8B 84 24 B4 02 00 00 57 55 8D 4C 24 34 50 51 C7 44 24 30 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F }
	condition:
		$c0
}

rule OpenSSL_BN_mod_exp_inverse
{	meta:
		author = "Maxx"
		description = "OpenSSL BN_mod_exp_inverse"
	strings:
		$c0 = { B8 18 00 00 00 E8 ?? ?? ?? ?? 53 55 56 57 8B 7C 24 38 33 C0 57 89 44 24 20 89 44 24 24 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 57 89 44 24 1C E8 ?? ?? ?? ?? 57 8B F0 E8 ?? ?? ?? ?? 57 89 44 24 28 E8 ?? ?? ?? ?? 57 8B E8 E8 ?? ?? ?? ?? 57 8B D8 E8 ?? ?? ?? ?? 8B F8 8B 44 24 54 50 89 7C 24 38 E8 ?? ?? ?? ?? 83 C4 20 89 44 24 24 85 C0 8B 44 24 2C 0F 84 78 05 00 00 85 C0 75 05 E8 ?? ?? ?? ?? 85 C0 89 44 24 1C 0F 84 63 05 00 00 8B 4C 24 14 6A 01 51 E8 ?? ?? ?? ?? 6A 00 57 E8 }
	condition:
		$c0
}

rule OpenSSL_DSA
{
	meta:
		author="_pusher_"
		date="2016-08"
	strings:	
		$a0 = "bignum_data" wide ascii nocase
		$a1 = "DSA_METHOD" wide ascii nocase
		$a2 = "PDSA" wide ascii nocase
		$a3 = "dsa_mod_exp" wide ascii nocase
		$a4 = "bn_mod_exp" wide ascii nocase
		$a5 = "dsa_do_verify" wide ascii nocase
		$a6 = "dsa_sign_setup" wide ascii nocase
		$a7 = "dsa_do_sign" wide ascii nocase
		$a8 = "dsa_paramgen" wide ascii nocase
		$a9 = "BN_MONT_CTX" wide ascii nocase
	condition:
		7 of ($a*)
}

rule FGint_RsaSign
{	meta:
		author = "Maxx"
		description = "FGint RsaSign"
	strings:
		$c0 = { 55 8B EC 83 C4 B8 53 56 57 89 4D F8 8B FA 89 45 FC 8B 75 0C 8B 5D 10 8B 45 FC E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 C0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 B8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 }
	condition:
		$c0
}


rule LockBox_RsaEncryptFile
{	meta:
		author = "Maxx"
		description = "LockBox RsaEncryptFile"
	strings:
		$c0 = { 55 8B EC 83 C4 F8 53 56 8B F1 8B DA 6A 20 8B C8 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 FC 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 68 FF FF 00 00 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8A 45 08 50 8B CE 8B 55 F8 8B 45 FC E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? C3 }
	condition:
		$c0
}

rule LockBox_DecryptRsaEx
{	meta:
		author = "Maxx"
		description = "LockBox DecryptRsaEx"
	strings:
		$c0 = { 55 8B EC 83 C4 F4 53 56 57 89 4D F8 89 55 FC 8B D8 33 C0 8A 43 04 0F B7 34 45 ?? ?? ?? ?? 0F B7 3C 45 ?? ?? ?? ?? 8B CE B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F4 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 55 FC 8B CE 8B 45 F4 E8 ?? ?? ?? ?? 6A 00 B1 02 8B D3 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B C7 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 8B C8 8B 55 F8 8B 45 F4 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 }
	condition:
		$c0
}

rule LockBox_EncryptRsaEx
{	meta:
		author = "Maxx"
		description = "LockBox EncryptRsaEx"
	strings:
		$c0 = { 55 8B EC 83 C4 F8 53 56 57 89 4D FC 8B FA 8B F0 33 C0 8A 46 04 0F B7 1C 45 ?? ?? ?? ?? 8B CB B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 F8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B D7 8B 4D 08 8B 45 F8 E8 ?? ?? ?? ?? 6A 01 B1 02 8B D6 8B 45 F8 E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 3B C3 7E 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 8B C8 8B 55 FC 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 F8 E8 }
	condition:
		$c0
}

rule LockBox_TlbRsaKey
{	meta:
		author = "Maxx"
		description = "LockBox TlbRsaKey"
	strings:
		$c0 = { 53 56 84 D2 74 08 83 C4 F0 E8 ?? ?? ?? ?? 8B DA 8B F0 33 D2 8B C6 E8 ?? ?? ?? ?? 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 0C 33 C0 8A 46 04 8B 15 ?? ?? ?? ?? 0F B7 0C 42 B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 46 10 8B C6 84 DB 74 0F E8 ?? ?? ?? ?? 64 8F 05 00 00 00 00 83 C4 0C 8B C6 5E 5B C3 }
	condition:
		$c0
}

rule BigDig_bpInit
{	meta:
		author = "Maxx"
		description = "BigDig bpInit"
	strings:
		$c0 = { 56 8B 74 24 0C 6A 04 56 E8 ?? ?? ?? ?? 8B C8 8B 44 24 10 83 C4 08 85 C9 89 08 75 04 33 C0 5E C3 89 70 08 C7 40 04 00 00 00 00 5E C3 }
	condition:
		$c0
}

rule BigDig_mpModExp
{	meta:
		author = "Maxx"
		description = "BigDig mpModExp"
	strings:
		$c0 = { 56 8B 74 24 18 85 F6 75 05 83 C8 FF 5E C3 53 55 8B 6C 24 18 57 56 55 E8 ?? ?? ?? ?? 8B D8 83 C4 08 BF 00 00 00 80 8B 44 9D FC 85 C7 75 04 D1 EF 75 F8 83 FF 01 75 08 BF 00 00 00 80 4B EB 02 D1 EF 8B 44 24 18 56 8B 74 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 4F 8D 6C 9D FC 8B 4C 24 24 8B 54 24 20 51 52 56 56 56 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C7 74 19 8B 44 24 24 8B 4C 24 20 8B 54 24 18 50 51 52 56 56 E8 ?? ?? ?? ?? 83 C4 14 83 FF 01 75 0B 4B BF 00 00 00 80 83 ED 04 EB }
	condition:
		$c0
}

rule BigDig_mpModInv
{	meta:
		author = "Maxx"
		description = "BigDig mpModInv"
	strings:
		$c0 = { 81 EC 2C 07 00 00 8D 84 24 CC 00 00 00 53 56 8B B4 24 44 07 00 00 57 56 6A 01 50 E8 ?? ?? ?? ?? 8B 8C 24 4C 07 00 00 56 8D 94 24 80 02 00 00 51 52 E8 ?? ?? ?? ?? 8D 84 24 BC 01 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 64 07 00 00 56 8D 4C 24 30 53 51 E8 ?? ?? ?? ?? 8D 54 24 38 56 52 BF 01 00 00 00 E8 ?? ?? ?? ?? 83 C4 34 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 78 02 00 00 56 8D 94 24 48 03 00 00 51 8D 84 24 18 04 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 BC 01 00 00 56 8D 94 }
	condition:
		$c0
}

rule BigDig_mpModMult
{	meta:
		author = "Maxx"
		description = "BigDig mpModMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 98 01 00 00 8D 54 24 00 56 8B B4 24 B0 01 00 00 57 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 C0 01 00 00 8B 94 24 B4 01 00 00 8D 3C 36 56 50 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 57 50 E8 ?? ?? ?? ?? 83 C4 2C 33 C0 5F 5E 81 C4 98 01 00 00 C3 }
	condition:
		$c0
}

rule BigDig_mpModulo
{	meta:
		author = "Maxx"
		description = "BigDig mpModulo"
	strings:
		$c0 = { 8B 44 24 10 81 EC 30 03 00 00 8B 8C 24 38 03 00 00 8D 54 24 00 56 8B B4 24 40 03 00 00 57 8B BC 24 4C 03 00 00 57 50 56 51 8D 84 24 B0 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 94 24 54 03 00 00 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 CC 01 00 00 56 51 E8 ?? ?? ?? ?? 83 C4 34 33 C0 5F 5E 81 C4 30 03 00 00 C3 }
	condition:
		$c0
}

rule BigDig_spModExpB
{	meta:
		author = "Maxx"
		description = "BigDig spModExpB"
	strings:
		$c0 = { 53 8B 5C 24 10 55 56 BE 00 00 00 80 85 F3 75 04 D1 EE 75 F8 8B 6C 24 14 8B C5 D1 EE 89 44 24 18 74 48 57 8B 7C 24 20 EB 04 8B 44 24 1C 57 50 50 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 F3 74 14 8B 4C 24 1C 57 55 8D 54 24 24 51 52 E8 ?? ?? ?? ?? 83 C4 10 D1 EE 75 D0 8B 44 24 14 8B 4C 24 1C 5F 5E 89 08 5D 33 C0 5B C3 8B 54 24 10 5E 5D 5B 89 02 33 C0 C3 }
	condition:
		$c0
}

rule BigDig_spModInv
{	meta:
		author = "Maxx"
		description = "BigDig spModInv"
	strings:
		$c0 = { 51 8B 4C 24 10 55 56 BD 01 00 00 00 33 F6 57 8B 7C 24 18 89 6C 24 0C 85 C9 74 42 53 8B C7 33 D2 F7 F1 8B C7 8B F9 8B DA 33 D2 F7 F1 8B CB 0F AF C6 03 C5 8B EE 8B F0 8B 44 24 10 F7 D8 85 DB 89 44 24 10 75 D7 85 C0 5B 7D 13 8B 44 24 1C 8B 4C 24 14 2B C5 5F 89 01 5E 33 C0 5D 59 C3 8B 54 24 14 5F 5E 33 C0 89 2A 5D 59 C3 }
	condition:
		$c0
}

rule BigDig_spModMult
{	meta:
		author = "Maxx"
		description = "BigDig spModMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 83 EC 08 8D 54 24 00 50 51 52 E8 ?? ?? ?? ?? 8B 44 24 24 6A 02 8D 4C 24 10 50 51 E8 ?? ?? ?? ?? 8B 54 24 24 89 02 33 C0 83 C4 20 C3 }
	condition:
		$c0
}

rule CryptoPP_ApplyFunction
{	meta:
		author = "Maxx"
		description = "CryptoPP ApplyFunction"
	strings:
		$c0 = { 51 8D 41 E4 56 8B 74 24 0C 83 C1 F0 50 51 8B 4C 24 18 C7 44 24 0C 00 00 00 00 51 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5E 59 C2 08 00 }
		$c1 = { 51 53 56 8B F1 57 6A 00 C7 44 24 10 00 00 00 00 8B 46 04 8B 48 04 8B 5C 31 04 8D 7C 31 04 E8 ?? ?? ?? ?? 50 8B CF FF 53 10 8B 44 24 18 8D 56 08 83 C6 1C 52 56 8B 74 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B C6 5F 5E 5B 59 C2 08 00 }
	condition:
		any of them
}

rule CryptoPP_RsaFunction
{	meta:
		author = "Maxx"
		description = "CryptoPP RsaFunction"
	strings:
		$c0 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 9C 00 00 00 8B 84 24 B0 00 00 00 53 55 56 33 ED 8B F1 57 3B C5 89 B4 24 A8 00 00 00 89 6C 24 10 BF 01 00 00 00 74 18 C7 06 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 89 7C 24 10 89 AC 24 B4 00 00 00 8D 4E 04 E8 ?? ?? ?? ?? 8D 4E 10 89 BC 24 B4 00 00 00 E8 ?? ?? ?? ?? 8B 06 BB ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 48 04 C7 04 31 ?? ?? ?? ?? 8B 16 8B 42 04 8B 54 24 10 83 CA 02 8D 48 E0 89 54 24 10 89 4C 30 FC 89 5C 24 18 89 7C }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 1C 53 8B 5C 24 1C 56 8B F1 57 33 C9 89 74 24 10 3B C1 89 4C 24 0C 74 7B C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 3B D9 75 06 89 4C 24 28 EB 0E 8B 43 04 8B 50 0C 8D 44 1A 04 89 44 24 28 8B 56 3C C7 44 24 0C 07 00 00 00 8B 42 04 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 56 3C C7 46 38 ?? ?? ?? ?? 8B 42 04 C7 44 30 3C }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 18 56 8B F1 57 85 C0 89 74 24 0C C7 44 24 08 00 00 00 00 74 63 C7 46 04 ?? ?? ?? ?? C7 46 3C ?? ?? ?? ?? C7 46 30 ?? ?? ?? ?? C7 46 34 ?? ?? ?? ?? 8B 46 3C C7 44 24 08 07 00 00 00 8B 48 04 C7 44 31 3C ?? ?? ?? ?? 8B 56 3C 8B 42 08 C7 44 30 3C ?? ?? ?? ?? 8B 4E 3C C7 46 38 ?? ?? ?? ?? 8B 51 04 C7 44 32 3C ?? ?? ?? ?? 8B 46 3C 8B 48 08 C7 44 31 3C ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 8D 7E 04 6A 00 8B CF }
	condition:
		any of them
}

rule CryptoPP_Integer_constructor
{	meta:
		author = "Maxx"
		description = "CryptoPP Integer constructor"
	strings:
		$c0 = { 8B 44 24 08 56 83 F8 08 8B F1 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 4C 24 0C 89 46 04 C7 46 08 00 00 00 00 89 08 8B 0E 8B 46 04 83 C4 04 49 74 0F 57 8D 78 04 33 C0 F3 AB 8B C6 5F 5E C2 08 00 8B C6 5E C2 08 00 }
		$c1 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 89 74 24 04 C7 06 ?? ?? ?? ?? 6A 08 C7 44 24 14 00 00 00 00 C7 46 08 02 00 00 00 E8 ?? ?? ?? ?? 89 46 0C C7 46 10 00 00 00 00 C7 06 ?? ?? ?? ?? 8B 46 0C 83 C4 04 C7 40 04 00 00 00 00 8B 4E 0C 8B C6 5E C7 01 00 00 00 00 8B 4C 24 04 64 89 0D 00 00 00 00 83 C4 10 C3 }
		$c2 = { 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B F1 57 89 74 24 08 C7 06 ?? ?? ?? ?? 8B 7C 24 1C C7 44 24 14 00 00 00 00 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 85 D2 89 56 08 76 12 8D 04 95 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 04 EB 02 33 C0 89 46 0C 8B 4F 10 89 4E 10 }
		$c3 = { 56 57 8B 7C 24 0C 8B F1 8B CF E8 ?? ?? ?? ?? 83 F8 08 77 09 8B 14 85 ?? ?? ?? ?? EB 37 83 F8 10 77 07 BA 10 00 00 00 EB 2B 83 F8 20 77 07 BA 20 00 00 00 EB 1F 83 F8 40 77 07 BA 40 00 00 00 EB 13 48 50 E8 ?? ?? ?? ?? BA 01 00 00 00 8B C8 83 C4 04 D3 E2 8D 04 95 00 00 00 00 89 16 50 E8 ?? ?? ?? ?? 8B 16 89 46 04 8B 4F 08 83 C4 04 89 4E 08 8B 4F 04 85 D2 76 0D 2B C8 8B 3C 01 89 38 83 C0 04 4A 75 F5 8B C6 5F 5E C2 04 00 }
	condition:
		any of them
}

rule RijnDael_AES
{	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}

rule RijnDael_AES_CHAR
{	meta:
		author = "_pusher_"
		description = "RijnDael AES (check2) [char]"
		date = "2016-06"
	strings:
		$c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
	condition:
		$c0
}

rule ARIA_SB2
{	meta:
		author = "spelissier"
		description = "Aria SBox 2"
		date = "2020-12"
		reference="http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf#page=7"
	strings:
		$c0 = { E2 4E 54 FC 94 C2 4A CC 62 0D 6A 46 3C 4D 8B D1 5E FA 64 CB B4 97 BE 2B BC 77 2E 03 D3 19 59 C1 }
	condition:
		$c0
}

rule RijnDael_AES_CHAR_inv
{	meta:
		author = "_pusher_"
		description = "RijnDael AES S-inv [char]"
		//needs improvement
		date = "2016-07"
	strings:
		$c0 = { 48 38 47 00 88 17 33 D2 8A 56 0D 8A 92 48 38 47 00 88 57 01 33 D2 8A 56 0A 8A 92 48 38 47 00 88 57 02 33 D2 8A 56 07 8A 92 48 38 47 00 88 57 03 33 D2 8A 56 04 8A 92 }
	condition:
		$c0
}

rule RsaRef2_NN_modExp
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modExp"
	strings:
		$c0 = { 81 EC 1C 02 00 00 53 55 56 8B B4 24 30 02 00 00 57 8B BC 24 44 02 00 00 57 8D 84 24 A4 00 00 00 56 50 E8 ?? ?? ?? ?? 8B 9C 24 4C 02 00 00 57 53 8D 8C 24 B4 00 00 00 56 8D 94 24 3C 01 00 00 51 52 E8 ?? ?? ?? ?? 57 53 8D 84 24 4C 01 00 00 56 8D 8C 24 D4 01 00 00 50 51 E8 ?? ?? ?? ?? 8D 54 24 50 57 52 E8 ?? ?? ?? ?? 8B 84 24 78 02 00 00 8B B4 24 74 02 00 00 50 56 C7 44 24 60 01 00 00 00 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 44 8B E9 89 4C 24 18 85 ED 0F 8C AF 00 00 00 8D 34 AE 89 74 24 }
	condition:
		any of them
}

rule RsaRef2_NN_modInv
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modInv"
	strings:
		$c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 84 24 ?? 00 00 00 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 BC 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 4C 24 2C 53 51 E8 ?? ?? ?? ?? 8D 54 24 34 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 ED 00 00 00 8D 44 24 0C 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C 24 2C 01 }
	condition:
		$c0
}

rule RsaRef2_NN_modMult
{	meta:
		author = "Maxx"
		description = "RsaRef2 NN_modMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 68 08 01 00 00 8D 4C 24 2C 6A 00 51 E8 ?? ?? ?? ?? 83 C4 30 5E 81 C4 08 01 00 00 C3 }
	condition:
		$c0
}

rule RsaRef2_RsaPrivateDecrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateDecrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8B 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6B 8A 4C 24 09 B8 02 00 00 00 3A C8 75 5E 8D 4E FF 3B C8 76 0D 8A 54 04 08 84 D2 74 05 40 3B C1 72 F3 40 3B C6 73 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A 8D 51 0B }
	condition:
		$c0
}

rule RsaRef2_RsaPrivateEncrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateEncrypt"
	strings:
		$c0 = { 8B 44 24 14 8B 54 24 10 81 EC 80 00 00 00 8D 4A 0B 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 80 00 00 00 C3 8B CE B8 02 00 00 00 2B CA C6 44 24 04 00 49 C6 44 24 05 01 3B C8 76 23 53 55 8D 69 FE 57 8B CD 83 C8 FF 8B D9 8D 7C 24 12 C1 E9 02 F3 AB 8B CB 83 E1 03 F3 AA 8D 45 02 5F 5D 5B 52 8B 94 24 94 00 00 00 C6 44 04 08 00 8D 44 04 09 52 50 E8 ?? ?? ?? ?? 8B 8C 24 A4 00 00 00 8B 84 24 98 00 00 00 51 8B 8C 24 98 00 00 00 8D 54 24 14 56 52 50 51 E8 }
	condition:
		$c0
}

rule RsaRef2_RsaPublicDecrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicDecrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 8B 8C 24 94 00 00 00 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 50 8B 84 24 98 00 00 00 51 8D 4C 24 0C 50 8D 54 24 14 51 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8E 00 00 00 39 74 24 04 74 0D B8 06 04 00 00 5E 81 C4 84 00 00 00 C3 8A 44 24 08 84 C0 75 6E 80 7C 24 09 01 75 67 B8 02 00 00 00 8D 4E FF 3B C8 76 0D B2 FF 38 54 04 08 75 05 40 3B C1 72 F5 8A 4C 04 08 40 84 C9 75 45 8B 94 24 ?? 00 00 00 8B CE 2B C8 89 0A }
	condition:
		$c0
}

rule RsaRef2_RsaPublicEncrypt
{	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicEncrypt"
	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 53 8B 9C 24 98 00 00 00 57 8B 38 83 C7 07 8D 4B 0B C1 EF 03 3B CF 76 0E 5F B8 06 04 00 00 5B 81 C4 84 00 00 00 C3 8B D7 55 2B D3 56 BE 02 00 00 00 C6 44 24 14 00 8D 6A FF C6 44 24 15 02 3B EE 76 28 8B 84 24 AC 00 00 00 8D 4C 24 13 50 6A 01 51 E8 ?? ?? ?? ?? 8A 44 24 1F 83 C4 0C 84 C0 74 E1 88 44 34 14 46 3B F5 72 D8 8B 94 24 A0 00 00 00 53 8D 44 34 19 52 50 C6 44 34 20 00 E8 ?? ?? ?? ?? 8B 8C 24 B4 00 00 00 8B 84 24 A8 00 00 00 51 8B 8C 24 A8 00 }
	condition:
		$c0
}

rule RsaEuro_NN_modInv
{	meta:
		author = "Maxx"
		description = "RsaEuro NN_modInv"
	strings:
		$c0 = { 81 EC A4 04 00 00 53 56 8B B4 24 BC 04 00 00 57 8D 44 24 0C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 1C 01 00 00 BF 01 00 00 00 56 51 89 7C 24 1C E8 ?? ?? ?? ?? 8B 94 24 C8 04 00 00 56 8D 84 24 AC 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 9C 24 D8 04 00 00 56 8D 8C 24 B0 00 00 00 53 51 E8 ?? ?? ?? ?? 8D 94 24 B8 00 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 30 85 C0 0F 85 F8 00 00 00 8D 84 24 ?? 00 00 00 56 50 8D 8C 24 A0 01 00 00 56 8D 94 24 AC 02 00 00 51 8D 84 24 34 03 00 00 52 50 E8 ?? ?? ?? ?? 8D 8C }
	condition:
		$c0
}

rule RsaEuro_NN_modMult
{	meta:
		author = "Maxx"
		description = "RsaEuro NN_modMult"
	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 08 01 00 00 8D 54 24 00 56 8B B4 24 20 01 00 00 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 2C 01 00 00 56 8D 0C 36 50 8B 84 24 28 01 00 00 8D 54 24 1C 51 52 50 E8 ?? ?? ?? ?? 83 C4 24 5E 81 C4 08 01 00 00 C3 }
	condition:
		$c0
}

rule Miracl_Big_constructor
{	meta:
		author = "Maxx"
		description = "Miracl Big constructor"
	strings:
		$c0 = { 56 8B F1 6A 00 E8 ?? ?? ?? ?? 83 C4 04 89 06 8B C6 5E C3 }
	condition:
		$c0
}

rule Miracl_mirvar
{	meta:
		author = "Maxx"
		description = "Miracl mirvar"
	strings:
		$c0 = { 56 E8 ?? ?? ?? ?? 8B 88 18 02 00 00 85 C9 74 04 33 C0 5E C3 8B 88 8C 00 00 00 85 C9 75 0E 6A 12 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5E C3 8B 80 38 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F0 83 C4 08 85 F6 75 02 5E C3 8D 46 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 08 85 C0 74 0A 56 50 E8 ?? ?? ?? ?? 83 C4 08 8B C6 5E C3 }
		$c1 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 2C 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 40 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 46 18 6A 01 8D 0C 85 0C 00 00 00 51 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B D0 8B C8 83 E2 03 2B CA 83 C1 08 89 08 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
		$c2 = { 56 57 E8 ?? ?? ?? ?? 8B F0 8B 86 18 02 00 00 85 C0 74 05 5F 33 C0 5E C3 8B 56 1C 42 8B C2 89 56 1C 83 F8 18 7D 17 C7 44 86 20 17 00 00 00 8B 86 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 86 8C 00 00 00 85 C0 75 16 6A 12 E8 ?? ?? ?? ?? 8B 46 1C 83 C4 04 48 89 46 1C 5F 33 C0 5E C3 8B 86 A4 02 00 00 6A 01 50 E8 ?? ?? ?? ?? 8B F8 83 C4 08 85 FF 75 0C 8B 46 1C 5F 48 89 46 1C 33 C0 5E C3 8D 47 04 8B C8 8B D0 83 E1 03 2B D1 83 C2 08 89 10 8B 44 24 0C 85 C0 74 0A 57 50 E8 }
	condition:
		any of them
}

rule Miracl_mirsys_init
{	meta:
		author = "Maxx"
		description = "Miracl mirsys init"
	strings:
		$c0 = { 53 55 57 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB A3 ?? ?? ?? ?? 3B C3 75 06 5F 5D 33 C0 5B C3 89 58 1C A1 ?? ?? ?? ?? BD 01 00 00 00 89 58 20 A1 ?? ?? ?? ?? 8B 50 1C 42 89 50 1C A1 ?? ?? ?? ?? 8B 48 1C C7 44 88 20 1D 00 00 00 8B 15 ?? ?? ?? ?? 89 9A 14 02 00 00 A1 ?? ?? ?? ?? 89 98 70 01 00 00 8B 0D ?? ?? ?? ?? 89 99 78 01 00 00 8B 15 ?? ?? ?? ?? 89 9A 98 01 00 00 A1 ?? ?? ?? ?? 89 58 14 8B 44 24 14 3B C5 0F 84 6C 05 00 00 3D 00 00 00 80 0F 87 61 05 00 00 50 E8 }
	condition:
		$c0
}

/* //gives many false positives sorry Storm Shadow
rule x509_public_key_infrastructure_cert
{	meta:
		desc = "X.509 PKI Certificate"
		ext = "crt"
	strings:
		$c0 = { 30 82 ?? ?? 30 82 ?? ?? }
	condition: 
		$c0
}

rule pkcs8_private_key_information_syntax_standard
{	meta:
		desc = "Found PKCS #8: Private-Key"
		ext = "key"
	strings: 
		$c0 = { 30 82 ?? ?? 02 01 00 }
	condition:
		$c0
}
*/

rule BASE64_table {
	meta:
		author = "_pusher_"
		description = "Look for Base64 table"
		date = "2015-07"
		version = "0.1"
	strings:
		$c0 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F }
	condition:
		$c0
}

rule Delphi_Random {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 53 31 DB 69 93 ?? ?? ?? ?? 05 84 08 08 42 89 93 ?? ?? ?? ?? F7 E2 89 D0 5B C3 }
		//x64 rad
		$c1 = { 8B 05 ?? ?? ?? ?? 69 C0 05 84 08 08 83 C0 01 89 05 ?? ?? ?? ?? 8B C9 8B C0 48 0F AF C8 48 C1 E9 20 89 C8 C3 }
	condition:
		any of them
}

rule Delphi_RandomRange {
	meta:
		author = "_pusher_"
		description = "Look for RandomRange function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 56 8B F2 8B D8 3B F3 7D 0E 8B C3 2B C6 E8 ?? ?? ?? ?? 03 C6 5E 5B C3 8B C6 2B C3 E8 ?? ?? ?? ?? 03 C3 5E 5B C3 }
	condition:
		$c0
}

rule Delphi_FormShow {
	meta:
		author = "_pusher_"
		description = "Look for Form.Show function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 8B D8 B2 01 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 48 89 D9 B2 01 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_CompareCall {
	meta:
		author = "_pusher_"
		description = "Look for Compare string function"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 89 C6 89 D7 39 D0 0F 84 8F 00 00 00 85 F6 74 68 85 FF 74 6B 8B 46 FC 8B 57 FC 29 D0 77 02 01 C2 52 C1 EA 02 74 26 8B 0E 8B 1F 39 D9 75 58 4A 74 15 8B 4E 04 8B 5F 04 39 D9 75 4B 83 C6 08 83 C7 08 4A 75 E2 EB 06 83 C6 04 83 C7 04 5A 83 E2 03 74 22 8B 0E 8B 1F 38 D9 75 41 4A 74 17 38 FD 75 3A 4A 74 10 81 E3 00 00 FF 00 81 E1 00 00 FF 00 39 D9 75 27 01 C0 EB 23 8B 57 FC 29 D0 EB 1C 8B 46 FC 29 D0 EB 15 5A 38 D9 75 10 38 FD 75 0C C1 E9 10 C1 EB 10 38 D9 75 02 38 FD 5F 5E 5B C3 }
		//newer delphi
		$c1 = { 39 D0 74 30 85 D0 74 22 8B 48 FC 3B 4A FC 75 24 01 C9 01 C8 01 CA F7 D9 53 8B 1C 01 3B 1C 11 75 07 83 C1 04 78 F3 31 C0 5B C3}
		//x64
		$c2 = { 41 56 41 55 57 56 53 48 83 EC 20 48 89 D3 48 3B CB 75 05 48 33 C0 EB 74 48 85 C9 75 07 8B 43 FC F7 D8 EB 68 48 85 DB 75 05 8B 41 FC EB 5E 8B 79 FC 44 8B 6B FC 89 FE 41 3B F5 7E 03 44 89 EE E8 ?? ?? ?? ?? 49 89 C6 48 89 D9 E8 ?? ?? ?? ?? 48 89 C1 85 F6 7E 30 41 0F B7 06 0F B7 11 2B C2 85 C0 75 29 83 FE 01 74 1E 41 0F B7 46 02 0F B7 51 02 2B C2 85 C0 75 15 49 83 C6 04 48 83 C1 04 83 EE 02 85 F6 7F D0 90 8B C7 41 2B C5 48 83 C4 20 5B 5E 5F 41 5D 41 5E C3 }
 	condition:
		any of them
}

rule Delphi_Copy {
	meta:
		author = "_pusher_"
		description = "Look for Copy function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 85 C0 74 2D 8B 58 FC 85 DB 74 26 4A 7C 1B 39 DA 7D 1F 29 D3 85 C9 7C 19 39 D9 7F 11 01 C2 8B 44 24 08 E8 ?? ?? ?? ?? EB 11 31 D2 EB E5 89 D9 EB EB 8B 44 24 08 E8 ?? ?? ?? ?? 5B C2 04 00 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 44 89 C0 48 33 C9 48 85 D2 74 03 8B 4A FC 83 F8 01 7D 05 48 33 C0 EB 09 83 E8 01 3B C1 7E 02 89 C8 45 85 C9 7D 05 48 33 C9 EB 0A 2B C8 41 3B C9 7E 03 44 89 C9 49 89 D8 48 63 C0 48 8D 14 42 89 C8 4C 89 C1 41 89 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_IntToStr {
	meta:
		author = "_pusher_"
		description = "Look for IntToStr function"
		date = "2016-04"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 81 C4 00 FF FF FF 53 56 8B F2 8B D8 FF 75 0C FF 75 08 8D 85 00 FF FF FF E8 ?? ?? ?? ?? 8D 95 00 FF FF FF 8B C6 E8 ?? ?? ?? ?? EB 0E 8B 0E 8B C6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 E8 ?? ?? ?? ?? 33 D2 8A D3 3B C2 72 E3 5E 5B 8B E5 5D C2 08 00 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 48 85 D2 7D 10 48 89 D9 48 F7 DA 41 B0 01 E8 ?? ?? ?? ?? EB 0B 48 89 D9 4D 33 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		any of them
}


rule Delphi_StrToInt {
	meta:
		author = "_pusher_"
		description = "Look for StrToInt function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 56 83 C4 F4 8B D8 8B D4 8B C3 E8 ?? ?? ?? ?? 8B F0 83 3C 24 00 74 19 89 5C 24 04 C6 44 24 08 0B 8D 54 24 04 A1 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 8B C6 83 C4 0C 5E 5B C3 }
		//x64 rad
		$c1 = { 55 56 53 48 83 EC 40 48 8B EC 48 89 CB 48 89 D9 48 8D 55 3C E8 ?? ?? ?? ?? 89 C6 83 7D 3C 00 74 1B 48 89 5D 20 C6 45 28 11 48 8B 0D ?? ?? ?? ?? 48 8D 55 20 4D 33 C0 E8 ?? ?? ?? ?? 89 F0 48 8D 65 40 5B 5E 5D C3 }
	condition:
		any of them
}

rule Delphi_DecodeDate {
	meta:
		author = "_pusher_"
		description = "Look for DecodeDate (DecodeDateFully) function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 89 4D F4 89 55 F8 89 45 FC 8B 5D 08 FF 75 10 FF 75 0C 8D 45 E8 E8 ?? ?? ?? ?? 8B 4D EC 85 C9 7F 24 8B 45 FC 66 C7 00 00 00 8B 45 F8 66 C7 00 00 00 8B 45 F4 66 C7 00 00 00 66 C7 03 00 00 33 D2 E9 F2 00 00 00 8B C1 BE 07 00 00 00 99 F7 FE 42 66 89 13 49 66 BB 01 00 81 F9 B1 3A 02 00 7C 13 81 E9 B1 3A 02 00 66 81 C3 90 01 81 F9 B1 3A 02 00 7D ED 8D 45 F2 50 8D 45 F0 66 BA AC 8E 91 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 AC 8E 66 6B 45 F0 64 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA B5 05 E8 ?? ?? ?? ?? 66 8B 45 F0 C1 E0 02 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA 6D 01 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 6D 01 66 03 5D F0 8B C3 E8 ?? ?? ?? ?? 8B D0 33 C0 8A C2 8D 04 40 8D 34 C5 ?? ?? ?? ?? 66 B8 01 00 0F B7 C8 66 8B 4C 4E FE 66 89 4D F0 66 8B 4D F2 66 3B 4D F0 72 0B 66 8B 4D F0 66 29 4D F2 40 EB DF 8B 4D FC 66 89 19 8B 4D F8 66 89 01 66 8B 45 F2 40 8B 4D F4 66 89 01 8B C2 5E 5B 8B E5 5D C2 0C 00 }
		//x64
		$c1 = { 55 41 55 57 56 53 48 83 EC 30 48 8B EC 48 89 D3 4C 89 C6 4C 89 CF E8 ?? ?? ?? ?? 48 8B C8 48 C1 E9 20 85 C9 7F 23 66 C7 03 00 00 66 C7 06 00 00 66 C7 07 00 00 48 8B 85 80 00 00 00 66 C7 00 00 00 48 33 C0 E9 19 01 00 00 4C 8B 85 80 00 00 00 41 C7 C1 07 00 00 00 8B C1 99 41 F7 F9 66 83 C2 01 66 41 89 10 83 E9 01 66 41 BD 01 00 81 F9 B1 3A 02 00 7C 14 81 E9 B1 3A 02 00 66 41 81 C5 90 01 81 F9 B1 3A 02 00 7D EC 90 66 BA AC 8E 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E AC 8E 66 6B 45 2C 64 66 44 03 E8 0F B7 4D 2E 66 BA B5 05 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 48 0F B7 45 2C 03 C0 03 C0 66 44 03 E8 0F B7 4D 2E 66 BA 6D 01 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E 6D 01 66 44 03 6D 2C 44 89 E9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 0F B6 D0 48 8D 14 52 48 8D 14 D1 66 B9 01 00 4C 0F B7 C1 4E 0F B7 44 42 FE 66 44 89 45 2C 4C 0F B7 45 2E 66 44 3B 45 2C 72 10 4C 0F B7 45 2C 66 44 29 45 2E 66 }
	condition:
		any of them
}


rule Unknown_Random {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 52 8B 45 08 69 15 ?? ?? ?? ?? 05 84 08 08 42 89 15 ?? ?? ?? ?? F7 E2 8B C2 5A C9 C2 04 00 }
	condition:
		$c0
}

rule VC6_Random {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-02"
	strings:
		$c0 = { A1 ?? ?? ?? ?? 69 C0 FD 43 03 00 05 C3 9E 26 00 A3 ?? ?? ?? ?? C1 F8 10 25 FF 7F 00 00 C3 }
	condition:
		$c0
}

rule VC8_Random {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-01"
		version = "0.1"
	strings:
		$c0 = { E8 ?? ?? ?? ?? 8B 48 14 69 C9 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 8B C1 C1 E8 10 25 FF 7F 00 00 C3 }
	condition:
		$c0
}

rule DCP_RIJNDAEL_Init {
	meta:
		author = "_pusher_"
		description = "Look for DCP RijnDael Init"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 ?? ?? ?? ?? 8B D7 8B 4D FC 8B C3 8B 38 FF 57 ?? 85 F6 75 25 8D 43 38 33 C9 BA 10 00 00 00 E8 ?? ?? ?? ?? 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 ?? 8B C3 8B 10 FF 52 ?? EB 16 8D 53 38 8B C6 B9 10 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 ?? 5F 5E 5B 59 5D C2 04 00 }
	condition:
		$c0
}

rule DCP_RIJNDAEL_EncryptECB {
	meta:
		author = "_pusher_"
		description = "Look for DCP RijnDael EncryptECB"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 55 83 C4 B4 89 0C 24 8D 74 24 08 8D 7C 24 28 80 78 30 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0A 89 0F 8B CA 83 C1 04 8B 09 8D 5F 04 89 0B 8B CA 83 C1 08 8B 09 8D 5F 08 89 0B 83 C2 0C 8B 12 8D 4F 0C 89 11 8B 50 58 83 EA 02 85 D2 0F 82 3B 01 00 00 42 89 54 24 04 33 D2 8B 0F 8B DA C1 E3 02 33 4C D8 5C 89 0E 8D 4F 04 8B 09 33 4C D8 60 8D 6E 04 89 4D 00 8D 4F 08 8B 09 33 4C D8 64 8D 6E 08 89 4D 00 8D 4F 0C 8B 09 33 4C D8 68 8D 5E 0C 89 0B 33 C9 8A 0E 8D 0C 8D }
	condition:
		$c0
}

rule DCP_BLOWFISH_Init {
	meta:
		author = "_pusher_"
		description = "Look for DCP Blowfish Init"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 55 8B F2 8B F8 8B CF B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8B C3 8B 10 FF 52 34 8B C6 E8 ?? ?? ?? ?? 50 8B C6 E8 ?? ?? ?? ?? 8B D0 8B C3 59 8B 30 FF 56 3C 8B 43 3C 85 C0 79 03 83 C0 07 C1 F8 03 E8 ?? ?? ?? ?? 8B F0 8B D6 8B C3 8B 08 FF 51 40 8B 47 40 8B 6B 3C 3B C5 7D 0F 6A 00 8B C8 8B D6 8B C7 8B 38 FF 57 30 EB 0D 6A 00 8B D6 8B CD 8B C7 8B 38 FF 57 30 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 B9 FF 00 00 00 E8 ?? ?? ?? ?? 8B 53 3C 85 D2 79 03 83 C2 07 C1 FA 03 8B C6 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5D 5F 5E 5B C3 }
	condition:
		$c0
}


rule DCP_BLOWFISH_EncryptCBC {
	meta:
		author = "_pusher_"
		description = "Look for DCP Blowfish EncryptCBC"
		date = "2016-07"
	strings:
		$c0 = { 55 8B EC 83 C4 F0 53 56 57 89 4D F8 89 55 FC 8B D8 80 7B 34 00 75 16 B9 ?? ?? ?? ?? B2 01 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D 08 85 FF 79 03 83 C7 07 C1 FF 03 85 FF 7E 56 BE 01 00 00 00 6A 08 8B 45 FC 8B D6 4A C1 E2 03 03 C2 8D 4D F0 8D 53 54 E8 ?? ?? ?? ?? 8D 4D F0 8D 55 F0 8B C3 E8 ?? ?? ?? ?? 8B 55 F8 8B C6 48 C1 E0 03 03 D0 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 8D 53 54 8D 45 F0 B9 08 00 00 00 E8 ?? ?? ?? ?? 46 4F 75 AF 8B 75 08 81 E6 07 00 00 80 79 05 4E 83 CE F8 46 85 F6 74 26 8D 4D F0 8D 53 54 8B C3 E8 ?? ?? ?? ?? 56 8B 4D F8 03 4D 08 2B CE 8B 55 FC 03 55 08 2B D6 8D 45 F0 E8 ?? ?? ?? ?? 8D 45 F0 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C2 04 00 }
	condition:
		$c0
}

rule DCP_DES_Init {
	meta:
		author = "_pusher_"
		description = "Look for DCP Des Init"
		date = "2016-02"
	strings:
		$c0 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 FE F9 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 5C 85 F6 75 25 8D 43 38 33 C9 BA 08 00 00 00 E8 F3 A9 FA FF 8D 4B 38 8D 53 38 8B C3 8B 30 FF 56 6C 8B C3 8B 10 FF 52 48 EB 16 8D 53 38 8B C6 B9 08 00 00 00 E8 6E A7 FA FF 8B C3 8B 10 FF 52 48 5F 5E 5B 59 5D C2 04 00 }
		$c1 = { 55 8B EC 51 53 56 57 89 4D FC 8B FA 8B D8 8B 75 08 56 8B D7 8B 4D FC 8B C3 E8 EE D4 FF FF 8B D7 8B 4D FC 8B C3 8B 38 FF 57 74 85 F6 75 2B 8D 43 40 B9 FF 00 00 00 BA 08 00 00 00 E8 ?? ?? ?? ?? 8D 4B 40 8D 53 40 8B C3 8B 30 FF 96 84 00 00 00 8B C3 8B 10 FF 52 58 EB 16 8D 53 40 8B C6 B9 08 00 00 00 E8 ?? ?? ?? ?? 8B C3 8B 10 FF 52 58 5F 5E 5B 59 5D C2 04 00 }
	condition:
		any of them
}


rule DCP_DES_EncryptECB {
	meta:
		author = "_pusher_"
		description = "Look for DCP Des EncryptECB"
		date = "2016-02"
	strings:
		$c0 = { 53 80 78 ?? 00 75 16 B9 ?? ?? ?? 00 B2 01 A1 ?? ?? ?? 00 E8 ?? ?? ?? FF E8 ?? ?? ?? FF 8D 58 ?? 53 E8 ?? ?? FF FF 5B C3 }
	condition:
		any of them
}

rule Chacha_128_constant {
    meta:
		author = "spelissier"
		description = "Look for 128-bit key Chacha stream cipher constant"
		date = "2019-12"
		reference = "https://www.ecrypt.eu.org/stream/salsa20pf.html"
	strings:
		$c0 = "expand 16-byte k"
	condition:
		$c0
}

rule Chacha_256_constant {
    meta:
		author = "spelissier"
		description = "Look for 256-bit key Chacha stream cipher constant"
		date = "2019-12"
		reference = "https://tools.ietf.org/html/rfc8439#page-8"
	strings:
		$c0 = "expand 32-byte k"
		$split1 = "expand 3"
		$split2 = "2-byte k"
	condition:
		$c0 or ( $split1 and $split2 )
}

rule ecc_order {
    meta:
		author = "spelissier"
		description = "Look for known Elliptic curve orders"
		date = "2021-07"
		version = "0.2"
	strings:
		$secp192k1 = { FF FF FF FF FF FF FF FF FF FF FF FE 26 F2 FC 17 0F 69 46 6A 74 DE FD 8D}
		$secp192r1 = { FF FF FF FF FF FF FF FF FF FF FF FF 99 DE F8 36 14 6B C9 B1 B4 D2 28 31}
		$secp224k1 = { 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 DC E8 D2 EC 61 84 CA F0 A9 71 76 9F B1 F7}
		$secp224r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D}
		$secp256k1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 41 }
		$prime256v1 = { FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF BC E6 FA AD A7 17 9E 84 F3 B9 CA C2 FC 63 25 51 }
		$secp384r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF C7 63 4D 81 F4 37 2D DF 58 1A 0D B2 48 B0 A7 7A EC EC 19 6A CC C5 29 73 }
		$bls12_381_r = { 01 00 00 00 FF FF FF FF FE 5B FE FF 02 A4 BD 53 05 D8 A1 09 08 D8 39 33 48 7D 9D 29 53 A7 ED 73}
	condition:
		any of them
}

rule SHA3_constants {
	meta:
		author = "spelissier"
		description = "SHA-3 (Keccak) round constants"
		date = "2020-04"
		version = "0.1"
	strings:
		$c0  = { 0080008000000080 }
		$c1  = { 0a00008000000080 }
		$c2  = { 8080000000000080 }
		$c3  = { 8b00000000000080 }
		$c4  = { 8280000000000000 }
		$c5  = { 8980000000000080 }
		$c6  = { 0880008000000080 }
		$c7  = { 0980008000000000 }
		$c8  = { 0280000000000080 }
		$c9  = { 0a00008000000000 }
		$c10 = { 0380000000000080 }
		$c11 = { 8b80000000000000 }
		$c12 = { 0100008000000000 }
		$c13 = { 0a80000000000000 }
		$c14 = { 0980000000000080 }
		$c15 = { 8000000000000080 }
		$c16 = { 8800000000000000 }
		$c17 = { 8b80008000000000 }
		$c18 = { 8a00000000000000 }
		$c19 = { 8180008000000080 }
		$c20 = { 0100000000000000 }
		$c21 = { 8a80000000000080 }
	condition:
		10 of them
}

rule SHA3_interleaved {
	meta:
		author = "spelissier"
		description = "SHA-3 (Keccak) interleaved round constants"
		date = "2020-04"
		version = "0.1"
	strings:
		$c0  = { 010000008b800000 }
		$c1  = { 0000000081000080 }
		$c2  = { 0000000088000080 }
		$c3  = { 000000000b000000 }
		$c4  = { 0100000000800000 }
		$c5  = { 010000008b000000 }
		$c6  = { 0100000082800000 }
		$c7  = { 0000000003800000 }
		$c8  = { 010000008a000080 }
		$c9  = { 0000000082800080 }
		$c10 = { 0000000003800080 }
		$c11 = { 000000008b000080 }
		$c12 = { 0000000083000000 }
		$c13 = { 000000000a000000 }
		$c14 = { 0000000080800080 }
		$c15 = { 0100000082000080 }
		$c16 = { 010000000b000080 }
		$c17 = { 0100000088800080 }
		$c18 = { 0000000008000080 }
		$c19 = { 0100000000000000 }
		$c20 = { 0000000089000000 }
		$c21 = { 0100000081000080 }
	condition:
		10 of them
}

rule SipHash_big_endian_constants {
    meta:
		author = "spelissier"
		description = "Look for SipHash constants in big endian"
		date = "2020-07"
		reference = "https://131002.net/siphash/siphash.pdf#page=6"
	strings:
		$c0 = "uespemos"
		$c1 = "modnarod"
		$c2 = "arenegyl"
		$c3 = "setybdet"
	condition:
		2 of them
}