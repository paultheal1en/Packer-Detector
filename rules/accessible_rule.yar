import "pe"
import "dotnet"

// PECompact
rule packer_PECompact_v311_aplib1_full_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v311"
		configs="aplib1_full aplib1_resources aplib1_nofastdecoder lzma2 crc32 aplib1_checksum elfhash aplib9 aplib1"
	strings:
		$rule0 = {a4 b3 02 e8} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov bl, 2; call 0x41b8f6;  
		$rule1 = {8a 16 46 12 d2 c3} 
		// mov dl, byte ptr [esi]; inc esi; adc dl, dl; ret ;  
		$rule2 = {33 c9 41 e8} 
		// xor ecx, ecx; inc ecx; call 0x41b8f6;  
		$rule3 = {91 48 c1 e0 08 ac e8} 
		// xchg eax, ecx; dec eax; shl eax, 8; lodsb al, byte ptr [esi]; call 0x41b900;  
		$rule4 = {41 41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b884;  
		$rule5 = {b3 02 41 b0 10 e8} 
		// mov bl, 2; inc ecx; mov al, 0x10; call 0x41b8f6;  
		$rule6 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b884;  
		$rule7 = {95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b884;  
		$rule8 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x41b912;  
		$rule9 = {8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b884;  
		$rule10 = {41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b884;  
		
	condition:
		pe.is_32bit() and (7 of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_PECompact_v311_brieflz_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v311"
		config="brieflz"
	strings:
		$rule0 = {a4 3b fb 73} 
		// movsb byte ptr es:[edi], byte ptr [esi]; cmp edi, ebx; jae 0x41b9bd;  
		$rule1 = {33 c0 40 e8} 
		// xor eax, eax; inc eax; call 0x41b9a0;  
		$rule2 = {48 48 41 41 c1 e0 08 ac 40 56 8b f7 2b f0 f3 a4 5e eb} 
		// dec eax; dec eax; inc ecx; inc ecx; shl eax, 8; lodsb al, byte ptr [esi]; inc eax; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b977;  
		$rule3 = {92 ad 92 03 d2 42 c3} 
		// xchg eax, edx; lodsd eax, dword ptr [esi]; xchg eax, edx; add edx, edx; inc edx; ret ;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_PECompact_v311_ffce_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v311"
		config="ffce"
	strings:
		$rule0 = {13 c0 49 75} 
		// adc eax, eax; dec ecx; jne 0x41b8c1;  
		$rule1 = {a4 b1 03 e8} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov cl, 3; call 0x41b8ef;  
		$rule2 = {8d 7c 1d 00 8b eb 8b df e8} 
		// lea edi, [ebp + ebx]; mov ebp, ebx; mov ebx, edi; call 0x41b8ef;  
		$rule3 = {8d 5c 3d 00 03 c7 8b ef e8} 
		// lea ebx, [ebp + edi]; add eax, edi; mov ebp, edi; call 0x41b8ef;  
		$rule4 = {53 55 57 33 db 43 33 ed 8b c3 8d 7c 1d 00 8b eb 8b df e8} 
		// push ebx; push ebp; push edi; xor ebx, ebx; inc ebx; xor ebp, ebp; mov eax, ebx; lea edi, [ebp + ebx]; mov ebp, ebx; mov ebx, edi; call 0x41b8ef;  
		$rule5 = {5f 5d 5b 2b c1 73} 
		// pop edi; pop ebp; pop ebx; sub eax, ecx; jae 0x41b8bf;  
		$rule6 = {33 c9 41 e8} 
		// xor ecx, ecx; inc ecx; call 0x41b8ef;  
		$rule7 = {8b e8 3d 01 80 00 00 83 d9 ff 3d 81 07 00 00 83 d9 ff 56 8b f7 2b f0 f3 a4 5e 41 41 eb} 
		// mov ebp, eax; cmp eax, 0x8001; sbb ecx, -1; cmp eax, 0x781; sbb ecx, -1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; inc ecx; inc ecx; jmp 0x41b878;  
		$rule8 = {92 ad 92 03 d2 42 c3} 
		// xchg eax, edx; lodsd eax, dword ptr [esi]; xchg eax, edx; add edx, edx; inc edx; ret ;  
		$rule9 = {56 8b f7 2b f0 f3 a4 5e 41 41 eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; inc ecx; inc ecx; jmp 0x41b878;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_PECompact_v311_jcalg1_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v311"
		config="jcalg1"
	strings:
		$rule0 = {8b 1e 03 c3 d1 e3 83 d3 01 33 c3 83 c6 04 83 e9 04 74} 
		// mov ebx, dword ptr [esi]; add eax, ebx; shl ebx, 1; adc ebx, 1; xor eax, ebx; add esi, 4; sub ecx, 4; je 0x41baba;  
		$rule1 = {02 45 f7 aa eb} 
		// add al, byte ptr [ebp - 9]; stosb byte ptr es:[edi], al; jmp 0x41b967;  
		$rule2 = {33 c9 41 e8} 
		// xor ecx, ecx; inc ecx; call 0x41bad0;  
		$rule3 = {8b 16 83 c6 04 f9 13 d2 c3} 
		// mov edx, dword ptr [esi]; add esi, 4; stc ; adc edx, edx; ret ;  
		$rule4 = {56 8b f7 2b f0 f3 a4 5e e9} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b967;  
		$rule5 = {41 56 8b f7 2b f0 f3 a4 5e e9} 
		// inc ecx; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b967;  
		$rule6 = {49 8b c1 55 8b 4d fc 8b e8 33 c0 d3 e5 e8} 
		// dec ecx; mov eax, ecx; push ebp; mov ecx, dword ptr [ebp - 4]; mov ebp, eax; xor eax, eax; shl ebp, cl; call 0x41bae8;  
		$rule7 = {0b c5 5d 8b d8 e8} 
		// or eax, ebp; pop ebp; mov ebx, eax; call 0x41baf4;  
		$rule8 = {50 b9 02 00 00 00 e8} 
		// push eax; mov ecx, 2; call 0x41bae8;  
		$rule9 = {8b c8 41 41 58 0b c0 74} 
		// mov ecx, eax; inc ecx; inc ecx; pop eax; or eax, eax; je 0x41ba0d;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_PECompact_v3022_aplib1_full_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v3022"
		configs="aplib1_full brieflz inv ffce lzma aplib1_resources aplib1_exports aplib1_nofastdecoder copy lzma2 crc32 aplib1_checksum cipher2 cipher1 elfhash jcalg1 aplib9 aplib1"
	strings:
		$rule0 = {a4 b3 02 e8} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov bl, 2; call 0x41b884;  
		$rule1 = {8a 16 46 12 d2 c3} 
		// mov dl, byte ptr [esi]; inc esi; adc dl, dl; ret ;  
		$rule2 = {33 c9 41 e8} 
		// xor ecx, ecx; inc ecx; call 0x41b884;  
		$rule3 = {91 48 c1 e0 08 ac e8} 
		// xchg eax, ecx; dec eax; shl eax, 8; lodsb al, byte ptr [esi]; call 0x41b88e;  
		$rule4 = {41 41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b812;  
		$rule5 = {b3 02 41 b0 10 e8} 
		// mov bl, 2; inc ecx; mov al, 0x10; call 0x41b884;  
		$rule6 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b812;  
		$rule7 = {95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b812;  
		$rule8 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x41b8a0;  
		$rule9 = {8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b812;  
		$rule10 = {41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41b812;  
		
	condition:
		pe.is_32bit() and (7 of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_PECompact_v3022_expand_combined
{
	meta:
		packer="PECompact"
		generator="PackGenome"
		version="v3022"
		config="expand"
	strings:
		$rule0 = {8a 01 41 84 c0 75} 
		// mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404605;  
		$rule1 = {89 75 d4 3b f3 74} 
		// mov dword ptr [ebp - 0x2c], esi; cmp esi, ebx; je 0x406035;  
		$rule2 = {8b 06 89 45 e0 ff 37 50 e8} 
		// mov eax, dword ptr [esi]; mov dword ptr [ebp - 0x20], eax; push dword ptr [edi]; push eax; call 0x4060ac;  
		$rule3 = {59 59 84 c0 74} 
		// pop ecx; pop ecx; test al, al; je 0x406030;  
		$rule4 = {8b ff 55 8b ec 8b 45 08 85 c0 74} 
		// mov edi, edi; push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 8]; test eax, eax; je 0x4060d7;  
		$rule5 = {32 c0 5d c3} 
		// xor al, al; pop ebp; ret ;  
		$rule6 = {88 84 05 fc fe ff ff 40 3b c7 72} 
		// mov byte ptr [ebp + eax - 0x104], al; inc eax; cmp eax, edi; jb 0x40888d;  
		$rule7 = {c6 84 05 fc fe ff ff 20 40 3b c2 76} 
		// mov byte ptr [ebp + eax - 0x104], 0x20; inc eax; cmp eax, edx; jbe 0x4088b7;  
		$rule8 = {8b ff 55 8b ec 83 7d 08 00 74} 
		// mov edi, edi; push ebp; mov ebp, esp; cmp dword ptr [ebp + 8], 0; je 0x4059d3;  
		$rule9 = {8b ff 55 8b ec 56 8b 75 08 85 f6 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push esi; mov esi, dword ptr [ebp + 8]; test esi, esi; je 0x405957;  
		$rule10 = {6a e0 33 d2 58 f7 f6 3b 45 0c 72} 
		// push -0x20; xor edx, edx; pop eax; div esi; cmp eax, dword ptr [ebp + 0xc]; jb 0x40598b;  
		$rule11 = {0f af 75 0c 85 f6 75} 
		// imul esi, dword ptr [ebp + 0xc]; test esi, esi; jne 0x405976;  
		$rule12 = {5f 5b 5d c3} 
		// pop edi; pop ebx; pop ebp; ret ;  
		$rule13 = {42 8b ce 8d 79 01 8a 01 41 84 c0 75} 
		// inc edx; mov ecx, esi; lea edi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404605;  
		$rule14 = {2b cf 46 03 f1 8a 06 84 c0 75} 
		// sub ecx, edi; inc esi; add esi, ecx; mov al, byte ptr [esi]; test al, al; jne 0x4045fb;  
		$rule15 = {8b cb 8d 71 01 8a 01 41 84 c0 75} 
		// mov ecx, ebx; lea esi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404634;  
		$rule16 = {2b ce 8d 41 01 89 45 f8 80 fa 3d 74} 
		// sub ecx, esi; lea eax, [ecx + 1]; mov dword ptr [ebp - 8], eax; cmp dl, 0x3d; je 0x40467f;  
		$rule17 = {6a 01 50 e8} 
		// push 1; push eax; call 0x40593e;  
		$rule18 = {83 c4 0c 85 c0 75} 
		// add esp, 0xc; test eax, eax; jne 0x4046a9;  
		$rule19 = {8b 45 fc 6a 00 89 30 83 c0 04 89 45 fc e8} 
		// mov eax, dword ptr [ebp - 4]; push 0; mov dword ptr [eax], esi; add eax, 4; mov dword ptr [ebp - 4], eax; call 0x40599b;  
		$rule20 = {8b 45 f8 59 03 d8 8a 13 84 d2 75} 
		// mov eax, dword ptr [ebp - 8]; pop ecx; add ebx, eax; mov dl, byte ptr [ebx]; test dl, dl; jne 0x40462f;  
		$rule21 = {8b ff 55 8b ec 56 68 d4 37 41 00 68 cc 37 41 00 68 20 2c 41 00 6a 12 e8} 
		// mov edi, edi; push ebp; mov ebp, esp; push esi; push 0x4137d4; push 0x4137cc; push 0x412c20; push 0x12; call 0x405b04;  
		$rule22 = {83 4f f8 ff 80 67 0d f8 89 1f 8d 7f 38 89 5f cc 8d 47 e0 c7 47 d0 00 00 0a 0a c6 47 d4 0a 89 5f d6 88 5f da 3b c6 75} 
		// or dword ptr [edi - 8], 0xffffffff; and byte ptr [edi + 0xd], 0xf8; mov dword ptr [edi], ebx; lea edi, [edi + 0x38]; mov dword ptr [edi - 0x34], ebx; lea eax, [edi - 0x20]; mov dword ptr [edi - 0x30], 0xa0a0000; mov byte ptr [edi - 0x2c], 0xa; mov dword ptr [edi - 0x2a], ebx; mov byte ptr [edi - 0x26], bl; cmp eax, esi; jne 0x409510;  
		$rule23 = {53 68 a0 0f 00 00 8d 47 e0 50 e8} 
		// push ebx; push 0xfa0; lea eax, [edi - 0x20]; push eax; call 0x405d42;  
		$rule24 = {8b ff 55 8b ec 53 57 8b f9 8b 4d 08 c6 47 0c 00 8d 5f 04 85 c9 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push ebx; push edi; mov edi, ecx; mov ecx, dword ptr [ebp + 8]; mov byte ptr [edi + 0xc], 0; lea ebx, [edi + 4]; test ecx, ecx; je 0x402f78;  
		$rule25 = {8b c7 5f 5b 5d } 
		// mov eax, edi; pop edi; pop ebx; pop ebp; ret 4;  
		$rule26 = {ff 03 85 f6 74} 
		// inc dword ptr [ebx]; test esi, esi; je 0x4043e8;  
		$rule27 = {59 85 c0 74} 
		// pop ecx; test eax, eax; je 0x404408;  
		$rule28 = {8a 45 fe 84 c0 74} 
		// mov al, byte ptr [ebp - 2]; test al, al; je 0x404428;  
		$rule29 = {8b ff 55 8b ec 83 ec 10 56 ff 75 08 8d 4d f0 e8} 
		// mov edi, edi; push ebp; mov ebp, esp; sub esp, 0x10; push esi; push dword ptr [ebp + 8]; lea ecx, [ebp - 0x10]; call 0x402f58;  
		$rule30 = {8a 4d ff 84 c9 75} 
		// mov cl, byte ptr [ebp - 1]; test cl, cl; jne 0x4043cb;  
		$rule31 = {42 89 30 8d 40 04 3b d1 75} 
		// inc edx; mov dword ptr [eax], esi; lea eax, [eax + 4]; cmp edx, ecx; jne 0x405e38;  
		$rule32 = {40 89 39 8d 49 04 3b c2 75} 
		// inc eax; mov dword ptr [ecx], edi; lea ecx, [ecx + 4]; cmp eax, edx; jne 0x404eac;  
		
	condition:
		pe.is_32bit() and (23 of them) and (pe.overlay.offset == 0 or for 16 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// MoleBox
rule packer_MoleBox
{
	meta:
		packer="MoleBox"
		generator="PackGenome"
		versions="v43018"
	strings:
		$rule0 = {0f b6 07 32 06 0f b6 c0 0f b6 57 04 32 90 c0 90 40 00 46 88 57 04 0f b6 47 01 32 06 0f b6 c0 0f b6 4f 05 32 88 c0 90 40 00 88 4d ef 46 88 4f 05 0f b6 47 02 32 06 0f b6 c0 0f b6 5f 06 32 98 c0 90 40 00 46 88 5f 06 0f b6 47 03 32 06 0f b6 c0 0f b6 4f 07 32 88 c0 90 40 00 46 88 4f 07 88 d0 32 06 0f b6 c0 0f b6 80 c0 90 40 00 32 47 01 46 88 47 01 32 55 ef 0f b6 c2 0f b6 80 c0 90 40 00 32 47 02 88 47 02 32 1e 0f b6 c3 0f b6 80 c0 90 40 00 32 47 03 46 88 47 03 32 0e 0f b6 c1 0f b6 80 c0 90 40 00 32 07 46 88 07 ff 4d f0 83 7d f0 ff 0f85} 
		// movzx eax, byte ptr [edi]; xor al, byte ptr [esi]; movzx eax, al; movzx edx, byte ptr [edi + 4]; xor dl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 4], dl; movzx eax, byte ptr [edi + 1]; xor al, byte ptr [esi]; movzx eax, al; movzx ecx, byte ptr [edi + 5]; xor cl, byte ptr [eax + 0x4090c0]; mov byte ptr [ebp - 0x11], cl; inc esi; mov byte ptr [edi + 5], cl; movzx eax, byte ptr [edi + 2]; xor al, byte ptr [esi]; movzx eax, al; movzx ebx, byte ptr [edi + 6]; xor bl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 6], bl; movzx eax, byte ptr [edi + 3]; xor al, byte ptr [esi]; movzx eax, al; movzx ecx, byte ptr [edi + 7]; xor cl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 7], cl; mov al, dl; xor al, byte ptr [esi]; movzx eax, al; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 1]; inc esi; mov byte ptr [edi + 1], al; xor dl, byte ptr [ebp - 0x11]; movzx eax, dl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 2]; mov byte ptr [edi + 2], al; xor bl, byte ptr [esi]; movzx eax, bl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 3]; inc esi; mov byte ptr [edi + 3], al; xor cl, byte ptr [esi]; movzx eax, cl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi]; inc esi; mov byte ptr [edi], al; dec dword ptr [ebp - 0x10]; cmp dword ptr [ebp - 0x10], -1; jne 0x40307b;  
		$rule1 = {89 f0 46 8b 4d 08 0f b6 04 08 8b 4d 10 88 04 0f 47 4a 83 fa ff 75} 
		// mov eax, esi; inc esi; mov ecx, dword ptr [ebp + 8]; movzx eax, byte ptr [eax + ecx]; mov ecx, dword ptr [ebp + 0x10]; mov byte ptr [edi + ecx], al; inc edi; dec edx; cmp edx, -1; jne 0x402935;  
		$rule2 = {8b 45 08 80 3c 30 80 75} 
		// mov eax, dword ptr [ebp + 8]; cmp byte ptr [eax + esi], 0x80; jne 0x40291f;  
		$rule3 = {8b 45 08 80 3c 30 00 75} 
		// mov eax, dword ptr [ebp + 8]; cmp byte ptr [eax + esi], 0; jne 0x40294e;  
		$rule4 = {8d 04 df 89 44 24 04 8b 45 08 89 04 24 e8} 
		// lea eax, [edi + ebx*8]; mov dword ptr [esp + 4], eax; mov eax, dword ptr [ebp + 8]; mov dword ptr [esp], eax; call 0x403065;  
		$rule5 = {43 39 f3 72} 
		// inc ebx; cmp ebx, esi; jb 0x40210d;  
		$rule6 = {55 89 e5 57 56 53 83 ec 08 8b 75 08 8b 7d 0c c7 45 f0 07 00 00 00 0f b6 07 32 06 0f b6 c0 0f b6 57 04 32 90 c0 90 40 00 46 88 57 04 0f b6 47 01 32 06 0f b6 c0 0f b6 4f 05 32 88 c0 90 40 00 88 4d ef 46 88 4f 05 0f b6 47 02 32 06 0f b6 c0 0f b6 5f 06 32 98 c0 90 40 00 46 88 5f 06 0f b6 47 03 32 06 0f b6 c0 0f b6 4f 07 32 88 c0 90 40 00 46 88 4f 07 88 d0 32 06 0f b6 c0 0f b6 80 c0 90 40 00 32 47 01 46 88 47 01 32 55 ef 0f b6 c2 0f b6 80 c0 90 40 00 32 47 02 88 47 02 32 1e 0f b6 c3 0f b6 80 c0 90 40 00 32 47 03 46 88 47 03 32 0e 0f b6 c1 0f b6 80 c0 90 40 00 32 07 46 88 07 ff 4d f0 83 7d f0 ff 0f85} 
		// push ebp; mov ebp, esp; push edi; push esi; push ebx; sub esp, 8; mov esi, dword ptr [ebp + 8]; mov edi, dword ptr [ebp + 0xc]; mov dword ptr [ebp - 0x10], 7; movzx eax, byte ptr [edi]; xor al, byte ptr [esi]; movzx eax, al; movzx edx, byte ptr [edi + 4]; xor dl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 4], dl; movzx eax, byte ptr [edi + 1]; xor al, byte ptr [esi]; movzx eax, al; movzx ecx, byte ptr [edi + 5]; xor cl, byte ptr [eax + 0x4090c0]; mov byte ptr [ebp - 0x11], cl; inc esi; mov byte ptr [edi + 5], cl; movzx eax, byte ptr [edi + 2]; xor al, byte ptr [esi]; movzx eax, al; movzx ebx, byte ptr [edi + 6]; xor bl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 6], bl; movzx eax, byte ptr [edi + 3]; xor al, byte ptr [esi]; movzx eax, al; movzx ecx, byte ptr [edi + 7]; xor cl, byte ptr [eax + 0x4090c0]; inc esi; mov byte ptr [edi + 7], cl; mov al, dl; xor al, byte ptr [esi]; movzx eax, al; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 1]; inc esi; mov byte ptr [edi + 1], al; xor dl, byte ptr [ebp - 0x11]; movzx eax, dl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 2]; mov byte ptr [edi + 2], al; xor bl, byte ptr [esi]; movzx eax, bl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi + 3]; inc esi; mov byte ptr [edi + 3], al; xor cl, byte ptr [esi]; movzx eax, cl; movzx eax, byte ptr [eax + 0x4090c0]; xor al, byte ptr [edi]; inc esi; mov byte ptr [edi], al; dec dword ptr [ebp - 0x10]; cmp dword ptr [ebp - 0x10], -1; jne 0x40307b;  
		$rule7 = {0f b6 07 32 06 0f b6 d0 0f b6 47 04 32 82 c0 90 40 00 46 88 47 04 0f b6 47 01 32 06 0f b6 d0 0f b6 47 05 32 82 c0 90 40 00 46 88 47 05 0f b6 47 02 32 06 0f b6 d0 0f b6 47 06 32 82 c0 90 40 00 88 47 06 0f b6 47 03 32 46 01 0f b6 d0 0f b6 47 07 32 82 c0 90 40 00 88 47 07 83 c4 08 5b 5e 5f 5d c3} 
		// movzx eax, byte ptr [edi]; xor al, byte ptr [esi]; movzx edx, al; movzx eax, byte ptr [edi + 4]; xor al, byte ptr [edx + 0x4090c0]; inc esi; mov byte ptr [edi + 4], al; movzx eax, byte ptr [edi + 1]; xor al, byte ptr [esi]; movzx edx, al; movzx eax, byte ptr [edi + 5]; xor al, byte ptr [edx + 0x4090c0]; inc esi; mov byte ptr [edi + 5], al; movzx eax, byte ptr [edi + 2]; xor al, byte ptr [esi]; movzx edx, al; movzx eax, byte ptr [edi + 6]; xor al, byte ptr [edx + 0x4090c0]; mov byte ptr [edi + 6], al; movzx eax, byte ptr [edi + 3]; xor al, byte ptr [esi + 1]; movzx edx, al; movzx eax, byte ptr [edi + 7]; xor al, byte ptr [edx + 0x4090c0]; mov byte ptr [edi + 7], al; add esp, 8; pop ebx; pop esi; pop edi; pop ebp; ret ;  
		$rule8 = {8b 45 08 0f b6 54 30 01 c1 e2 08 0f b6 04 30 09 d0 89 c3 83 e3 0f c1 e8 04 8b 55 10 01 fa 89 d1 29 c1 89 c8 83 e8 0f 89 5c 24 08 89 44 24 04 89 14 24 e8} 
		// mov eax, dword ptr [ebp + 8]; movzx edx, byte ptr [eax + esi + 1]; shl edx, 8; movzx eax, byte ptr [eax + esi]; or eax, edx; mov ebx, eax; and ebx, 0xf; shr eax, 4; mov edx, dword ptr [ebp + 0x10]; add edx, edi; mov ecx, edx; sub ecx, eax; mov eax, ecx; sub eax, 0xf; mov dword ptr [esp + 8], ebx; mov dword ptr [esp + 4], eax; mov dword ptr [esp], edx; call 0x4069f0;  
		$rule9 = {01 df 83 c6 02 3b 75 0c 0f 9c c0 3b 7d 14 0f 9c c2 0f b6 c0 85 d0 0f85} 
		// add edi, ebx; add esi, 2; cmp esi, dword ptr [ebp + 0xc]; setl al; cmp edi, dword ptr [ebp + 0x14]; setl dl; movzx eax, al; test eax, edx; jne 0x402907;  
		$rule10 = {3b 75 0c 0f 9c c0 3b 7d 14 0f 9c c2 0f b6 c0 85 d0 0f85} 
		// cmp esi, dword ptr [ebp + 0xc]; setl al; cmp edi, dword ptr [ebp + 0x14]; setl dl; movzx eax, al; test eax, edx; jne 0x402907;  
		$rule11 = {46 0f b6 04 06 46 89 c2 83 f8 ff 74} 
		// inc esi; movzx eax, byte ptr [esi + eax]; inc esi; mov edx, eax; cmp eax, -1; je 0x40298a;  
		$rule12 = {69 45 0c 0d 66 19 00 05 5f f3 6e 3c 89 45 0c 30 06 46 3b 75 ec 75} 
		// imul eax, dword ptr [ebp + 0xc], 0x19660d; add eax, 0x3c6ef35f; mov dword ptr [ebp + 0xc], eax; xor byte ptr [esi], al; inc esi; cmp esi, dword ptr [ebp - 0x14]; jne 0x401a07;  
		$rule13 = {0f b7 03 c1 e8 0c 74} 
		// movzx eax, word ptr [ebx]; shr eax, 0xc; je 0x401aca;  
		$rule14 = {0f b7 03 25 ff 0f 00 00 03 45 e4 8b 7d f0 8b 4d e8 01 3c 08 83 c3 02 39 d3 72} 
		// movzx eax, word ptr [ebx]; and eax, 0xfff; add eax, dword ptr [ebp - 0x1c]; mov edi, dword ptr [ebp - 0x10]; mov ecx, dword ptr [ebp - 0x18]; add dword ptr [eax + ecx], edi; add ebx, 2; cmp ebx, edx; jb 0x401aa8;  
		$rule15 = {46 0f b6 04 06 8b 4d 10 88 04 0f 47 46 eb} 
		// inc esi; movzx eax, byte ptr [esi + eax]; mov ecx, dword ptr [ebp + 0x10]; mov byte ptr [edi + ecx], al; inc edi; inc esi; jmp 0x40298a;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// nspack
rule packer_nspack
{
	meta:
		packer="nspack"
		generator="PackGenome"
		versions="v23 v37 v41"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c27d;  
		$rule1 = {8b 07 80 7a 01 00 74} 
		// mov eax, dword ptr [edi]; cmp byte ptr [edx + 1], 0; je 0x41c2a2;  
		$rule2 = {8a 1a 38 1f 75} 
		// mov bl, byte ptr [edx]; cmp byte ptr [edi], bl; jne 0x41c27d;  
		$rule3 = {8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 eb} 
		// mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; jmp 0x41c2ac;  
		$rule4 = {2b c7 03 c6 89 07 83 c7 05 80 eb e8 8b c3 } 
		// sub eax, edi; add eax, esi; mov dword ptr [edi], eax; add edi, 5; sub bl, 0xe8; mov eax, ebx; loop 0x41c282;  
		$rule5 = {8a 16 46 12 d2 c3} 
		// mov dl, byte ptr [esi]; inc esi; adc dl, dl; ret ;  
		$rule6 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41c4a2;  
		$rule7 = {33 c9 41 e8} 
		// xor ecx, ecx; inc ecx; call 0x41c514;  
		$rule8 = {91 48 c1 e0 08 ac 8b e8 e8} 
		// xchg eax, ecx; dec eax; shl eax, 8; lodsb al, byte ptr [esi]; mov ebp, eax; call 0x41c51e;  
		$rule9 = {41 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x41c4a2;  
		$rule10 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x41c530;  
		$rule11 = {83 d1 02 8b e8 eb} 
		// adc ecx, 2; mov ebp, eax; jmp 0x41c50a;  
		
	condition:
		pe.is_32bit() and (8 of them) and (pe.overlay.offset == 0 or for 5 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// mew
rule packer_mew_v12_lzma_special_combined
{
	meta:
		packer="mew"
		generator="PackGenome"
		version="v12"
		configs="lzma_special default no_strip_delphi no_strip_reloc no_pack_res"
	strings:
		$rule0 = {ac 3c 00 75} 
		// lodsb al, byte ptr [esi]; cmp al, 0; jne 0x4001ec;  
		$rule1 = {a4 b6 80 ff} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov dh, 0x80; call dword ptr [ebx];  
		$rule2 = {41 41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule3 = {b6 80 41 b0 10 ff} 
		// mov dh, 0x80; inc ecx; mov al, 0x10; call dword ptr [ebx];  
		$rule4 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x4001ca;  
		$rule5 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule6 = {95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule7 = {91 40 50 55 ff} 
		// xchg eax, ecx; inc eax; push eax; push ebp; call dword ptr [ebx - 0xc];  
		$rule8 = {ab 85 c0 75} 
		// stosd dword ptr es:[edi], eax; test eax, eax; jne 0x4001e2;  
		$rule9 = {56 ad 0f c8 40 59 74} 
		// push esi; lodsd eax, dword ptr [esi]; bswap eax; inc eax; pop ecx; je 0x4001d6;  
		$rule10 = {8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		
	condition:
		pe.is_32bit() and (7 of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_mew_v12_no_lzma_combined
{
	meta:
		packer="mew"
		generator="PackGenome"
		version="v12"
		config="no_lzma"
	strings:
		$rule0 = {a4 b6 80 ff} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov dh, 0x80; call dword ptr [ebx];  
		$rule1 = {41 41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule2 = {95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule3 = {b6 80 41 b0 10 ff} 
		// mov dh, 0x80; inc ecx; mov al, 0x10; call dword ptr [ebx];  
		$rule4 = {41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule5 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule6 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x4001ca;  
		$rule7 = {8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x400165;  
		$rule8 = {ac 3c 00 75} 
		// lodsb al, byte ptr [esi]; cmp al, 0; jne 0x4001e7;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 6 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// ZProtect
rule packer_ZProtect
{
	meta:
		packer="ZProtect"
		generator="PackGenome"
		versions="v160"
	strings:
		$rule0 = {88 17 c3} 
		// mov byte ptr [edi], dl; ret ;  
		$rule1 = {88 01 c3} 
		// mov byte ptr [ecx], al; ret ;  
		$rule2 = {88 16 c3} 
		// mov byte ptr [esi], dl; ret ;  
		$rule3 = {01 3a c3} 
		// add dword ptr [edx], edi; ret ;  
		$rule4 = {c6 00 00 c3} 
		// mov byte ptr [eax], 0; ret ;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// kkrunchy
rule packer_kkrunchy_v023a2
{
	meta:
		packer="kkrunchy"
		generator="PackGenome"
		versions="v023a2"
	strings:
		$rule0 = {0f 6f 1e 0f 6f 17 0f ed db 0f e5 d8 0f ed d9 0f 71 e3 01 0f ed d3 0f 7f 17 83 c6 08 83 c7 08 } 
		// movq mm3, qword ptr [esi]; movq mm2, qword ptr [edi]; paddsw mm3, mm3; pmulhw mm3, mm0; paddsw mm3, mm1; psraw mm3, 1; paddsw mm2, mm3; movq qword ptr [edi], mm2; add esi, 8; add edi, 8; loop 0x3e9d57;  
		$rule1 = {0f 6f 0e 0f f5 0f 0f 72 e1 08 0f fe c1 83 c6 08 83 c7 08 } 
		// movq mm1, qword ptr [esi]; pmaddwd mm1, qword ptr [edi]; psrad mm1, 8; paddd mm0, mm1; add esi, 8; add edi, 8; loop 0x3ea1cc;  
		$rule2 = {89 c2 c1 ea 11 25 fe ff 01 00 8d 44 86 10 3a 10 75} 
		// mov edx, eax; shr edx, 0x11; and eax, 0x1fffe; lea eax, [esi + eax*4 + 0x10]; cmp dl, byte ptr [eax]; jne 0x3e9d2a;  
		$rule3 = {0f 6e c0 0f 61 c0 0f 61 c0 0f 74 c9 0f 71 d1 0f 01 c9 0f 6f 1e 0f 6f 17 0f ed db 0f e5 d8 0f ed d9 0f 71 e3 01 0f ed d3 0f 7f 17 83 c6 08 83 c7 08 } 
		// movd mm0, eax; punpcklwd mm0, mm0; punpcklwd mm0, mm0; pcmpeqb mm1, mm1; psrlw mm1, 0xf; add ecx, ecx; movq mm3, qword ptr [esi]; movq mm2, qword ptr [edi]; paddsw mm3, mm3; pmulhw mm3, mm0; paddsw mm3, mm1; psraw mm3, 1; paddsw mm2, mm3; movq qword ptr [edi], mm2; add esi, 8; add edi, 8; loop 0x3e9d57;  
		$rule4 = {83 c0 04 3a 10 75} 
		// add eax, 4; cmp dl, byte ptr [eax]; jne 0x3e9d33;  
		$rule5 = {40 01 d0 eb} 
		// inc eax; add eax, edx; jmp 0x3ea131;  
		$rule6 = {8b 46 08 33 45 18 e8} 
		// mov eax, dword ptr [esi + 8]; xor eax, dword ptr [ebp + 0x18]; call 0x3e9d16;  
		$rule7 = {4f d0 eb 73} 
		// dec edi; shr bl, 1; jae 0x3ea022;  
		$rule8 = {8b 45 4c c1 e0 0c 2b 44 95 30 6b c0 07 80 fa 03 74} 
		// mov eax, dword ptr [ebp + 0x4c]; shl eax, 0xc; sub eax, dword ptr [ebp + edx*4 + 0x30]; imul eax, eax, 7; cmp dl, 3; je 0x3e9fb3;  
		$rule9 = {89 44 9d 30 4b 79} 
		// mov dword ptr [ebp + ebx*4 + 0x30], eax; dec ebx; jns 0x3ea1b3;  
		$rule10 = {32 07 69 c0 93 01 00 01 eb} 
		// xor al, byte ptr [edi]; imul eax, eax, 0x1000193; jmp 0x3ea013;  
		$rule11 = {0f bf 1f 0f bf 16 0f af da 01 d8 66 a7 } 
		// movsx ebx, word ptr [edi]; movsx edx, word ptr [esi]; imul ebx, edx; add eax, ebx; cmpsw word ptr [esi], word ptr es:[edi]; loop 0x3ea214;  
		$rule12 = {8b 4d 00 f7 65 0c 0f ac d0 0c 8b 09 0f c9 2b 4d 08 31 d2 39 c8 77} 
		// mov ecx, dword ptr [ebp]; mul dword ptr [ebp + 0xc]; shrd eax, edx, 0xc; mov ecx, dword ptr [ecx]; bswap ecx; sub ecx, dword ptr [ebp + 8]; xor edx, edx; cmp eax, ecx; ja 0x3e9d98;  
		$rule13 = {31 c0 3b 45 5c 75} 
		// xor eax, eax; cmp eax, dword ptr [ebp + 0x5c]; jne 0x3e9f0b;  
		$rule14 = {8b 45 3c 80 fc 08 83 d0 00 e8} 
		// mov eax, dword ptr [ebp + 0x3c]; cmp ah, 8; adc eax, 0; call 0x3e9d79;  
		$rule15 = {89 55 4c 66 ff 45 5c d1 ea 10 db 73} 
		// mov dword ptr [ebp + 0x4c], edx; inc word ptr [ebp + 0x5c]; shr edx, 1; adc bl, bl; jae 0x3e9f74;  
		$rule16 = {53 8b 4d 4c c1 e1 10 83 e9 80 89 4d 50 31 d2 8b 45 4c c1 e0 0c 2b 44 95 30 6b c0 07 80 fa 03 74} 
		// push ebx; mov ecx, dword ptr [ebp + 0x4c]; shl ecx, 0x10; sub ecx, -0x80; mov dword ptr [ebp + 0x50], ecx; xor edx, edx; mov eax, dword ptr [ebp + 0x4c]; shl eax, 0xc; sub eax, dword ptr [ebp + edx*4 + 0x30]; imul eax, eax, 7; cmp dl, 3; je 0x3e9fb3;  
		$rule17 = {8b 45 4c d1 65 14 01 45 14 ff 4d 1c 0f85} 
		// mov eax, dword ptr [ebp + 0x4c]; shl dword ptr [ebp + 0x14], 1; add dword ptr [ebp + 0x14], eax; dec dword ptr [ebp + 0x1c]; jne 0x3ea07f;  
		$rule18 = {89 45 3c 5b e9} 
		// mov dword ptr [ebp + 0x3c], eax; pop ebx; jmp 0x3e9ed8;  
		$rule19 = {89 46 08 8b 1e 8b 7d 04 8a 77 ff 3a 73 01 74} 
		// mov dword ptr [esi + 8], eax; mov ebx, dword ptr [esi]; mov edi, dword ptr [ebp + 4]; mov dh, byte ptr [edi - 1]; cmp dh, byte ptr [ebx + 1]; je 0x3e9ffa;  
		$rule20 = {8a 70 01 3a 70 fd 76} 
		// mov dh, byte ptr [eax + 1]; cmp dh, byte ptr [eax - 3]; jbe 0x3e9d3e;  
		$rule21 = {01 45 08 29 45 0c eb} 
		// add dword ptr [ebp + 8], eax; sub dword ptr [ebp + 0xc], eax; jmp 0x3e9d9c;  
		$rule22 = {b2 00 66 89 13 fe 03 05 00 00 01 00 e8} 
		// mov dl, 0; mov word ptr [ebx], dx; inc byte ptr [ebx]; add eax, 0x10000; call 0x3e9d16;  
		$rule23 = {89 45 28 66 ab 8b 45 28 3d 90 01 00 00 76} 
		// mov dword ptr [ebp + 0x28], eax; stosw word ptr es:[edi], ax; mov eax, dword ptr [ebp + 0x28]; cmp eax, 0x190; jbe 0x3ea0d1;  
		$rule24 = {0f b6 d2 89 10 40 c3} 
		// movzx edx, dl; mov dword ptr [eax], edx; inc eax; ret ;  
		$rule25 = {fe 03 05 00 00 01 00 e8} 
		// inc byte ptr [ebx]; add eax, 0x10000; call 0x3e9d16;  
		$rule26 = {8b 5d 24 0f b6 1b fe c7 8a 4d 1c d3 eb 19 d2 3b 5d 14 75} 
		// mov ebx, dword ptr [ebp + 0x24]; movzx ebx, byte ptr [ebx]; inc bh; mov cl, byte ptr [ebp + 0x1c]; shr ebx, cl; sbb edx, edx; cmp ebx, dword ptr [ebp + 0x14]; jne 0x3ea0b6;  
		$rule27 = {8b 45 2c 31 d0 29 d0 eb} 
		// mov eax, dword ptr [ebp + 0x2c]; xor eax, edx; sub eax, edx; jmp 0x3ea0b9;  
		$rule28 = {66 ab 8b 45 28 3d 90 01 00 00 76} 
		// stosw word ptr es:[edi], ax; mov eax, dword ptr [ebp + 0x28]; cmp eax, 0x190; jbe 0x3ea0d1;  
		$rule29 = {83 e8 04 0f b6 d2 89 10 40 c3} 
		// sub eax, 4; movzx edx, dl; mov dword ptr [eax], edx; inc eax; ret ;  
		$rule30 = {89 45 0c 42 80 7d 0f 00 75} 
		// mov dword ptr [ebp + 0xc], eax; inc edx; cmp byte ptr [ebp + 0xf], 0; jne 0x3e9daf;  
		
	condition:
		pe.is_32bit() and (21 of them) and (pe.overlay.offset == 0 or for 14 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_kkrunchy_v023a
{
	meta:
		packer="kkrunchy"
		generator="PackGenome"
		versions="v023a"
	strings:
		$rule0 = {51 8b 45 08 c1 e8 0b 8b 4d 00 0f af 03 8b 09 0f c9 2b 4d 04 39 c8 8b 4d 0c 76} 
		// push ecx; mov eax, dword ptr [ebp + 8]; shr eax, 0xb; mov ecx, dword ptr [ebp]; imul eax, dword ptr [ebx]; mov ecx, dword ptr [ecx]; bswap ecx; sub ecx, dword ptr [ebp + 4]; cmp eax, ecx; mov ecx, dword ptr [ebp + 0xc]; jbe 0x3eb2ad;  
		$rule1 = {c1 e8 1f 59 c3} 
		// shr eax, 0x1f; pop ecx; ret ;  
		$rule2 = {89 45 08 31 c0 b4 08 2b 03 d3 e8 01 03 31 c0 eb} 
		// mov dword ptr [ebp + 8], eax; xor eax, eax; mov ah, 8; sub eax, dword ptr [ebx]; shr eax, cl; add dword ptr [ebx], eax; xor eax, eax; jmp 0x3eb2bc;  
		$rule3 = {01 45 04 29 45 08 8b 03 d3 e8 29 03 83 c8 ff f6 45 0b ff 75} 
		// add dword ptr [ebp + 4], eax; sub dword ptr [ebp + 8], eax; mov eax, dword ptr [ebx]; shr eax, cl; sub dword ptr [ebx], eax; or eax, 0xffffffff; test byte ptr [ebp + 0xb], 0xff; jne 0x3eb2cd;  
		$rule4 = {53 8d 1c 93 ff} 
		// push ebx; lea ebx, [ebx + edx*4]; call esi;  
		$rule5 = {ff 45 00 c1 65 08 08 c1 65 04 08 c1 e8 1f 59 c3} 
		// inc dword ptr [ebp]; shl dword ptr [ebp + 8], 8; shl dword ptr [ebp + 4], 8; shr eax, 0x1f; pop ecx; ret ;  
		$rule6 = {8d 0c 48 f6 c2 02 75} 
		// lea ecx, [eax + ecx*2]; test dl, 2; jne 0x3eb2e2;  
		$rule7 = {8d 0c 48 f6 c2 10 74} 
		// lea ecx, [eax + ecx*2]; test dl, 0x10; je 0x3eb20f;  
		$rule8 = {ff 45 0c 91 aa 83 c9 ff 8d 5c 8d 18 ff} 
		// inc dword ptr [ebp + 0xc]; xchg eax, ecx; stosb byte ptr es:[edi], al; or ecx, 0xffffffff; lea ebx, [ebp + ecx*4 + 0x18]; call esi;  
		$rule9 = {31 c9 41 ff 4d 0c 8d 9c 8d a0 00 00 00 ff} 
		// xor ecx, ecx; inc ecx; dec dword ptr [ebp + 0xc]; lea ebx, [ebp + ecx*4 + 0xa0]; call esi;  
		$rule10 = {50 31 c9 41 89 ca e8} 
		// push eax; xor ecx, ecx; inc ecx; mov edx, ecx; call 0x3eb2d2;  
		$rule11 = {49 49 78} 
		// dec ecx; dec ecx; js 0x3eb244;  
		$rule12 = {41 91 8d 9d a0 08 00 00 e8} 
		// inc ecx; xchg eax, ecx; lea ebx, [ebp + 0x8a0]; call 0x3eb2dc;  
		$rule13 = {3d 00 08 00 00 83 d9 ff 83 f8 60 83 d9 ff 89 45 10 56 89 fe 29 c6 f3 a4 5e eb} 
		// cmp eax, 0x800; sbb ecx, -1; cmp eax, 0x60; sbb ecx, -1; mov dword ptr [ebp + 0x10], eax; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x3eb1d4;  
		$rule14 = {83 c3 40 31 d2 42 e8} 
		// add ebx, 0x40; xor edx, edx; inc edx; call 0x3eb2d2;  
		$rule15 = {31 d2 42 e8} 
		// xor edx, edx; inc edx; call 0x3eb2d2;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// petite
rule packer_petite
{
	meta:
		packer="petite"
		generator="PackGenome"
		versions="v24"
	strings:
		$rule0 = {ac 32 c3 aa 4b 7e} 
		// lodsb al, byte ptr [esi]; xor al, bl; stosb byte ptr es:[edi], al; dec ebx; jle 0x40dbdb;  
		$rule1 = {56 8d 34 38 f3 a4 5e eb} 
		// push esi; lea esi, [eax + edi]; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x40db77;  
		$rule2 = {03 cd 2b d9 72} 
		// add ecx, ebp; sub ebx, ecx; jb 0x40dbdb;  
		$rule3 = {8b c1 8b 4c 24 0c e8} 
		// mov eax, ecx; mov ecx, dword ptr [esp + 0xc]; call 0x40dbe1;  
		$rule4 = {f7 d0 3b 44 24 04 83 d5 01 3b 44 24 08 83 d5 00 89 04 24 e8} 
		// not eax; cmp eax, dword ptr [esp + 4]; adc ebp, 1; cmp eax, dword ptr [esp + 8]; adc ebp, 0; mov dword ptr [esp], eax; call 0x40dbe1;  
		$rule5 = {8b 16 83 ee fc 13 d2 c3} 
		// mov edx, dword ptr [esi]; sub esi, -4; adc edx, edx; ret ;  
		$rule6 = {8b 04 24 41 eb} 
		// mov eax, dword ptr [esp]; inc ecx; jmp 0x40dbb4;  
		$rule7 = {83 c1 02 03 cd 2b d9 72} 
		// add ecx, 2; add ecx, ebp; sub ebx, ecx; jb 0x40dbdb;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 5 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// VMProtect
rule packer_VMProtect_v246_fast_integrity_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="fast_integrity"
	strings:
		$rule0 = {9c 8d 64 24 04 (e9|e8)} 
		// pushfd ; lea esp, [esp + 4]; jmp 0x423f3f;  
		$rule1 = {8d 64 24 04 (0f83|0f87)} 
		// lea esp, [esp + 4]; jae 0x431c9d;  
		$rule2 = {9c e8} 
		// pushfd ; call 0x42f9fd;  
		$rule3 = {8d 64 24 24 (0f83|e8)} 
		// lea esp, [esp + 0x24]; jae 0x423920;  
		$rule4 = {11 c9 [0-6] [0-10] [0-2] [0-10] 8d 64 24 e8} 
		// adc ecx, ecx; lea esp, [esp + 0x2c];  
		$rule5 = {8b 45 00 [0-2] [0-10] [0-8] [0-4] 8b (50|51|52|53|54|55|56|57) 04 [0-2] f7 (d0|d1|d2|d3|d4|d5|d6|d7) (e8|e9)} 
		// mov eax, dword ptr [ebp]; mov edx, dword ptr [ebp + 4]; not eax;  
		$rule6 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-10] [0-2] [0-8] 8d 64 24 e9} 
		// push dword ptr [esp + 0x34]; pop dword ptr [ebp]; lea esp, [esp + 0x44];  
		$rule7 = {8f 44 24 [0-2] [0-2] [0-2] ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] [0-2] [0-2] 8d 64 24 e9} 
		// pop dword ptr [esp + 4]; push dword ptr [esp + 0x28]; pop dword ptr [ebp]; lea esp, [esp + 0x3c];  
		$rule8 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] [0-10] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x1c]; pop dword ptr [ebp]; lea esp, [esp + 0x48];  
		
	condition:
		pe.is_32bit() and (6 of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v246_fast_import_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="fast_import"
	strings:
		$rule0 = {9c 8d 64 24 04 (0f88|0f83)} 
		// pushfd ; lea esp, [esp + 4]; js 0x435982;  
		$rule1 = {8d 64 24 24 (e8|0f8f)} 
		// lea esp, [esp + 0x24]; call 0x43da97;  
		$rule2 = {8d 64 24 0c (0f83|e8)} 
		// lea esp, [esp + 0xc]; jae 0x4353ad;  
		$rule3 = {8d 64 24 04 0f83} 
		// lea esp, [esp + 4]; jae 0x4353c2;  
		$rule4 = {8d 64 24 28 e8} 
		// lea esp, [esp + 0x28]; call 0x43da97;  
		$rule5 = {ff 74 24 [0-2] 8f 45 00 [0-10] [0-2] [0-8] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 4]; pop dword ptr [ebp]; lea esp, [esp + 0x34];  
		$rule6 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] [0-2] 8d 64 24 30 e9} 
		// push dword ptr [esp + 4]; pop dword ptr [ebp]; lea esp, [esp + 0x30];  
		$rule7 = {8b 6c 24 [0-2] c6 44 24 04 ?? [0-2] [0-6] ff 74 24 } 
		// mov ebp, dword ptr [esp + 0x30]; mov byte ptr [esp + 4], 0x20; push dword ptr [esp + 0x3c];  
		
	condition:
		pe.is_32bit() and (5 of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v246_best_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="best"
	strings:
		$rule0 = {52 8b 55 e8 c1 ea 0b 0f af 10 39 55 e4 0f83} 
		// push edx; mov edx, dword ptr [ebp - 0x18]; shr edx, 0xb; imul edx, dword ptr [eax]; cmp dword ptr [ebp - 0x1c], edx; jae 0x42588b;  
		$rule1 = {89 55 e8 ba 00 08 00 00 2b 10 c1 ea 05 01 10 e8} 
		// mov dword ptr [ebp - 0x18], edx; mov edx, 0x800; sub edx, dword ptr [eax]; shr edx, 5; add dword ptr [eax], edx; call 0x42a388;  
		$rule2 = {29 55 e8 29 55 e4 8b 10 c1 ea 05 29 10 e8} 
		// sub dword ptr [ebp - 0x18], edx; sub dword ptr [ebp - 0x1c], edx; mov edx, dword ptr [eax]; shr edx, 5; sub dword ptr [eax], edx; call 0x42a388;  
		$rule3 = {11 d2 83 e9 01 0f85} 
		// adc edx, edx; sub ecx, 1; jne 0x423c22;  
		$rule4 = {9f 11 d2 9e d1 df 83 e9 01 0f85} 
		// lahf ; adc edx, edx; sahf ; rcr edi, 1; sub ecx, 1; jne 0x423d54;  
		$rule5 = {53 57 89 c3 ba 01 00 00 00 89 d7 d3 e7 8d 04 93 e8} 
		// push ebx; push edi; mov ebx, eax; mov edx, 1; mov edi, edx; shl edi, cl; lea eax, [ebx + edx*4]; call 0x429691;  
		$rule6 = {89 d0 29 f8 5f 5b c3} 
		// mov eax, edx; sub eax, edi; pop edi; pop ebx; ret ;  
		$rule7 = {89 55 e4 05 01 00 00 00 e8} 
		// mov dword ptr [ebp - 0x1c], edx; add eax, 1; call 0x42a388;  
		$rule8 = {53 57 51 89 c3 ba 01 00 00 00 31 ff 8d 04 93 e8} 
		// push ebx; push edi; push ecx; mov ebx, eax; mov edx, 1; xor edi, edi; lea eax, [ebx + edx*4]; call 0x429691;  
		$rule9 = {89 f8 59 d3 c0 5f 5b c3} 
		// mov eax, edi; pop ecx; rol eax, cl; pop edi; pop ebx; ret ;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v246_fast_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="fast"
	strings:
		$rule0 = {9c 8d 64 24 08 (0f85|0f83)} 
		// pushfd ; lea esp, [esp + 8]; jne 0x428579;  
		$rule1 = {9c 8d 64 24 04 (e8|0f82)} 
		// pushfd ; lea esp, [esp + 4]; call 0x431c28;  
		$rule2 = {8d 64 24 04 e8} 
		// lea esp, [esp + 4]; call 0x431260;  
		$rule3 = {60 (e8|e9)} 
		// pushal ; call 0x42e05a;  
		$rule4 = {8d 64 24 08 (0f87|e8)} 
		// lea esp, [esp + 8]; ja 0x42cdf4;  
		$rule5 = {9c (e9|e8)} 
		// pushfd ; jmp 0x431e41;  
		$rule6 = {57 e8} 
		// push edi; call 0x42cdeb;  
		$rule7 = {aa [0-10] [0-2] [0-2] [0-2] b3 02 e8} 
		// stosb byte ptr es:[edi], al; mov bl, 2;  
		$rule8 = {10 c0 [0-2] [0-2] 8d 64 24 0f83} 
		// adc al, al; lea esp, [esp + 0x10];  
		$rule9 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x44]; pop dword ptr [ebp]; lea esp, [esp + 0x50];  
		$rule10 = {8b 45 00 [0-12] [0-6] 8b (50|51|52|53|54|55|56|57) 04 [0-2] f7 d0 [0-2] [0-10] [0-2] f7 (d0|d1|d2|d3|d4|d5|d6|d7) e9} 
		// mov eax, dword ptr [ebp]; mov edx, dword ptr [ebp + 4]; not eax; not edx;  
		$rule11 = {89 45 00 [0-6] [0-2] ff 74 24 04 8d 64 24 e9} 
		// mov dword ptr [ebp], eax; push dword ptr [esp + 4]; lea esp, [esp + 0x48];  
		$rule12 = {aa [0-10] [0-6] [0-2] [0-2] 8d 64 24 (e9|e8)} 
		// stosb byte ptr es:[edi], al; lea esp, [esp + 0x2c];  
		$rule13 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-8] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x30]; pop dword ptr [ebp]; lea esp, [esp + 0x40];  
		$rule14 = {ff 74 24 [0-2] 8f 45 00 [0-8] [0-8] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x20]; pop dword ptr [ebp]; lea esp, [esp + 0x28];  
		
	condition:
		pe.is_32bit() and (10 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v246_full_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="full"
	strings:
		$rule0 = {8d 64 24 04 (0f85|e8)} 
		// lea esp, [esp + 4]; jne 0x4260ef;  
		$rule1 = {9c (e9|e8)} 
		// pushfd ; jmp 0x441a35;  
		$rule2 = {60 e9} 
		// pushal ; jmp 0x44188b;  
		$rule3 = {8d 64 24 08 e8} 
		// lea esp, [esp + 8]; call 0x441387;  
		$rule4 = {ff 74 24 [0-2] 8f 45 00 [0-8] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x3c]; pop dword ptr [ebp]; lea esp, [esp + 0x44];  
		$rule5 = {31 c9 [0-2] [0-8] 8d 64 24 04 e8} 
		// xor ecx, ecx; lea esp, [esp + 4];  
		$rule6 = {ff 74 24 [0-2] 8f 45 00 e9} 
		// push dword ptr [esp + 0x40]; pop dword ptr [ebp];  
		$rule7 = {11 c9 [0-2] [0-2] [0-2] [0-2] 8d 64 24 30 (e9|e8)} 
		// adc ecx, ecx; lea esp, [esp + 0x30];  
		$rule8 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] [0-2] [0-10] 8d 64 24 e9} 
		// push dword ptr [esp + 8]; pop dword ptr [ebp]; lea esp, [esp + 0x34];  
		$rule9 = {ff 74 24 [0-2] 8f 45 00 [0-6] [0-8] 8d 64 24 e9} 
		// push dword ptr [esp + 0x50]; pop dword ptr [ebp]; lea esp, [esp + 0x54];  
		$rule10 = {aa [0-2] [0-2] [0-2] [0-2] 8d 64 24 e9} 
		// stosb byte ptr es:[edi], al; lea esp, [esp + 0x48];  
		$rule11 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x14]; pop dword ptr [ebp]; lea esp, [esp + 0x40];  
		$rule12 = {ff 74 24 [0-2] 8f 45 00 [0-2] [0-10] [0-14] [0-2] 8d 64 24 e9} 
		// push dword ptr [esp + 0x1c]; pop dword ptr [ebp]; lea esp, [esp + 0x44];  
		$rule13 = {8a (48|49|4a|4b|4c|4d|4e|4f) 04 [0-8] [0-2] [0-2] 83 ed 02 (e9|e8)} 
		// mov cl, byte ptr [ebp + 4]; sub ebp, 2;  
		$rule14 = {8f 44 24 [0-2] [0-2] [0-10] ff 74 24 [0-2] 8f 45 00 [0-2] [0-2] ff 74 24 [0-2] 8d 64 24 e9} 
		// pop dword ptr [esp + 0x28]; push dword ptr [esp + 0x30]; pop dword ptr [ebp]; push dword ptr [esp + 8]; lea esp, [esp + 0x40];  
		$rule15 = {89 (50|51|52|53|54|55|56|57) 00 68 ?? ?? ?? ?? 8d 64 24 (0f85|e9)} 
		// mov dword ptr [ebp], edx; push 0x4816d755; lea esp, [esp + 0x44];  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v246_fast_memory_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v246"
		config="fast_memory"
	strings:
		$rule0 = {8d 64 24 04 0f83} 
		// lea esp, [esp + 4]; jae 0x424ff7;  
		$rule1 = {8d 64 24 08 0f83} 
		// lea esp, [esp + 8]; jae 0x41e11b;  
		$rule2 = {60 e8} 
		// pushal ; call 0x430e76;  
		$rule3 = {ff 74 24 [0-2] 8f 45 00 [0-10] 8d 64 24 e9} 
		// push dword ptr [esp + 0x14]; pop dword ptr [ebp]; lea esp, [esp + 0x18];  
		$rule4 = {aa [0-12] [0-10] 8d 64 24 (e9|e8)} 
		// stosb byte ptr es:[edi], al; lea esp, [esp + 0x28];  
		$rule5 = {8f 45 00 [0-2] 8d 64 24 e9} 
		// pop dword ptr [ebp]; lea esp, [esp + 4];  
		$rule6 = {83 c5 04 [0-10] ff 74 24 [0-2] [0-2] [0-8] [0-8] [0-2] 8d 64 24 e9} 
		// add ebp, 4; push dword ptr [esp + 0x24]; lea esp, [esp + 0x2c];  
		$rule7 = {68 ?? ?? ?? ?? 8b 45 00 (e8|e9)} 
		// push 0xc1567157; mov eax, dword ptr [ebp];  
		
	condition:
		pe.is_32bit() and (5 of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v340_compress_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v340"
		config="compress"
	strings:
		$rule0 = {83 e9 01 e9} 
		// sub ecx, 1; jmp 0x6bb8c3;  
		$rule1 = {89 4d e8 e9} 
		// mov dword ptr [ebp - 0x18], ecx; jmp 0x65613e;  
		$rule2 = {88 55 ff e9} 
		// mov byte ptr [ebp - 1], dl; jmp 0x878db8;  
		$rule3 = {89 7d c0 e9} 
		// mov dword ptr [ebp - 0x40], edi; jmp 0x616b98;  
		$rule4 = {89 4d cc (e9|0f85)} 
		// mov dword ptr [ebp - 0x34], ecx; jmp 0x866e07;  
		$rule5 = {83 6d c0 01 (e9|0f85)} 
		// sub dword ptr [ebp - 0x40], 1; jmp 0x5ab120;  
		$rule6 = {8b 7d c0 e9} 
		// mov edi, dword ptr [ebp - 0x40]; jmp 0x826fc0;  
		$rule7 = {66 89 14 0f e9} 
		// mov word ptr [edi + ecx], dx; jmp 0x6aa677;  
		$rule8 = {8d 54 12 01 (0f84|e9)} 
		// lea edx, [edx + edx + 1]; je 0x676ea6;  
		$rule9 = {66 89 3c 0a e9} 
		// mov word ptr [edx + ecx], di; jmp 0x6901af;  
		$rule10 = {83 eb 03 e9} 
		// sub ebx, 3; jmp 0x8be95b;  
		$rule11 = {8b 55 08 e9} 
		// mov edx, dword ptr [ebp + 8]; jmp 0x89ae95;  
		$rule12 = {66 89 0f e9} 
		// mov word ptr [edi], cx; jmp 0x676ea0;  
		$rule13 = {83 45 f0 01 (e9|0f84)} 
		// add dword ptr [ebp - 0x10], 1; jmp 0x5d7b3b;  
		$rule14 = {89 4d c8 e9} 
		// mov dword ptr [ebp - 0x38], ecx; jmp 0x676e04;  
		$rule15 = {8b 5d ec e9} 
		// mov ebx, dword ptr [ebp - 0x14]; jmp 0x69d790;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v340_memory_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v340"
		config="memory"
	strings:
		$rule0 = {89 7d c0 e9} 
		// mov dword ptr [ebp - 0x40], edi; jmp 0x7be4ee;  
		$rule1 = {88 55 ff e9} 
		// mov byte ptr [ebp - 1], dl; jmp 0xb51543;  
		$rule2 = {89 4d e8 e9} 
		// mov dword ptr [ebp - 0x18], ecx; jmp 0x7abf7c;  
		$rule3 = {89 55 cc e9} 
		// mov dword ptr [ebp - 0x34], edx; jmp 0x81992b;  
		$rule4 = {83 e9 01 (0f85|e9)} 
		// sub ecx, 1; jne 0x8456ed;  
		$rule5 = {83 6d c8 01 e9} 
		// sub dword ptr [ebp - 0x38], 1; jmp 0x7abf68;  
		$rule6 = {83 6d c0 01 (0f85|e9)} 
		// sub dword ptr [ebp - 0x40], 1; jne 0x7ef12b;  
		$rule7 = {2b c2 2b (f0|f1|f2|f3|f4|f5|f6|f7) 66 8b d7 e9} 
		// sub eax, edx; sub esi, edx; mov dx, di;  
		$rule8 = {8b 55 f8 [0-4] [0-10] [0-12] 0f b6 1a [0-2] [0-10] c1 e6 08 [0-2] c1 (e0|e1|e2|e3|e4|e5|e6|e7) 08 [0-6] [0-2] 0b f3 e9} 
		// mov edx, dword ptr [ebp - 8]; movzx ebx, byte ptr [edx]; shl esi, 8; shl eax, 8; or esi, ebx;  
		$rule9 = {8b 55 f0 8b (48|49|4a|4b|4c|4d|4e|4f) e8 [0-4] [0-2] 83 45 e4 02 e9} 
		// mov edx, dword ptr [ebp - 0x10]; mov ecx, dword ptr [ebp - 0x18]; add dword ptr [ebp - 0x1c], 2;  
		$rule10 = {89 55 c8 0f b7 fa [0-6] 8b d0 [0-2] [0-6] c1 ea 0b 0f af d7 e9} 
		// mov dword ptr [ebp - 0x38], edx; movzx edi, dx; mov edx, eax; shr edx, 0xb; imul edx, edi;  
		$rule11 = {8b ca 8b (f8|f9|fa|fb|fc|fd|fe|ff) [0-2] [0-2] [0-4] d1 f9 83 e7 01 e9} 
		// mov ecx, edx; mov edi, edx; sar ecx, 1; and edi, 1;  
		$rule12 = {0f b7 8c 5f 80 01 00 00 [0-4] [0-4] [0-10] 89 4d c8 [0-6] [0-12] [0-8] 0f b7 d1 [0-8] [0-4] [0-4] c1 e9 0b [0-10] [0-2] [0-6] 0f af ca e9} 
		// movzx ecx, word ptr [edi + ebx*2 + 0x180]; mov dword ptr [ebp - 0x38], ecx; movzx edx, cx; shr ecx, 0xb; imul ecx, edx;  
		$rule13 = {0f b6 11 [0-2] [0-6] c1 e6 08 c1 (e0|e1|e2|e3|e4|e5|e6|e7) 08 0b f2 [0-2] [0-8] [0-4] 41 [0-8] [0-4] 89 4d f8 [0-10] [0-6] [0-4] 0f b7 8c 5f [0-8] [0-4] [0-4] [0-10] 89 4d [0-2] [0-6] [0-12] [0-8] 0f b7 d1 [0-8] [0-4] 8b c8 c1 e9 0b [0-10] [0-2] [0-6] 0f af ca e9} 
		// movzx edx, byte ptr [ecx]; shl esi, 8; shl eax, 8; or esi, edx; inc ecx; mov dword ptr [ebp - 8], ecx; movzx ecx, word ptr [edi + ebx*2 + 0x180]; mov dword ptr [ebp - 0x38], ecx; movzx edx, cx; mov ecx, eax; shr ecx, 0xb; imul ecx, edx;  
		$rule14 = {89 4d c8 [0-4] [0-4] 0f b7 d1 8b c8 c1 e9 0b 0f af ca e9} 
		// mov dword ptr [ebp - 0x38], ecx; movzx edx, cx; mov ecx, eax; shr ecx, 0xb; imul ecx, edx;  
		$rule15 = {0f b7 8c 5f [0-8] [0-8] [0-6] [0-2] 89 4d c8 [0-6] [0-6] [0-8] 0f b7 d1 8b c8 [0-6] c1 e9 0b 0f af ca e9} 
		// movzx ecx, word ptr [edi + ebx*2 + 0x1b0]; mov dword ptr [ebp - 0x38], ecx; movzx edx, cx; mov ecx, eax; shr ecx, 0xb; imul ecx, edx;  
		$rule16 = {2b c1 [0-4] [0-4] [0-10] 2b (f0|f1|f2|f3|f4|f5|f6|f7) 8b 4d c8 [0-2] [0-4] d1 [0-4] [0-12] [0-8] [0-2] 66 2b ca [0-2] 66 89 8c 5f b0 01 00 00 (e9|0f83)} 
		// sub eax, ecx; sub esi, ecx; mov ecx, dword ptr [ebp - 0x38]; mov dx, cx; sub cx, dx; mov word ptr [edi + ebx*2 + 0x1b0], cx;  
		$rule17 = {89 4d [0-2] [0-6] [0-6] [0-8] 0f b7 d1 8b c8 [0-6] c1 e9 0b 0f af ca e9} 
		// mov dword ptr [ebp - 0x38], ecx; movzx edx, cx; mov ecx, eax; shr ecx, 0xb; imul ecx, edx;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_VMProtect_v340_import_combined
{
	meta:
		packer="VMProtect"
		generator="PackGenome"
		version="v340"
		config="import"
	strings:
		$rule0 = {88 55 ff e9} 
		// mov byte ptr [ebp - 1], dl; jmp 0x83ace8;  
		$rule1 = {88 14 39 e9} 
		// mov byte ptr [ecx + edi], dl; jmp 0x76d15e;  
		$rule2 = {8b 5d 08 e9} 
		// mov ebx, dword ptr [ebp + 8]; jmp 0x85229a;  
		$rule3 = {89 55 cc e9} 
		// mov dword ptr [ebp - 0x34], edx; jmp 0x86bbd2;  
		$rule4 = {89 7d c0 (e9|0f84)} 
		// mov dword ptr [ebp - 0x40], edi; jmp 0x8c1b82;  
		$rule5 = {83 e9 01 (e9|0f85)} 
		// sub ecx, 1; jmp 0x863608;  
		$rule6 = {89 4d cc e9} 
		// mov dword ptr [ebp - 0x34], ecx; jmp 0x8506c2;  
		$rule7 = {83 6d c0 01 (0f85|e9)} 
		// sub dword ptr [ebp - 0x40], 1; jne 0x808a4d;  
		$rule8 = {83 6d c8 01 e9} 
		// sub dword ptr [ebp - 0x38], 1; jmp 0x79ea15;  
		$rule9 = {66 89 14 0f e9} 
		// mov word ptr [edi + ecx], dx; jmp 0x88fc86;  
		$rule10 = {8d 54 12 01 e9} 
		// lea edx, [edx + edx + 1]; jmp 0x5cee9f;  
		$rule11 = {89 55 e4 e9} 
		// mov dword ptr [ebp - 0x1c], edx; jmp 0x88fc86;  
		$rule12 = {83 eb 03 e9} 
		// sub ebx, 3; jmp 0x85550d;  
		
	condition:
		pe.is_32bit() and (9 of them) and (pe.overlay.offset == 0 or for 6 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Themida
rule packer_Themida_v304_protect_secureEngine_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v304"
		configs="protect_secureEngine_FISH_WHITE full_FISH_WHITE protect_all_FISH_WHITE"
	strings:
		$rule0 = {8a 06 46 88 07 47 bb 02 00 00 00 00 d2 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; mov ebx, 2; add dl, dl; jne 0x7d207e;  
		$rule1 = {b8 01 00 00 00 00 d2 75} 
		// mov eax, 1; add dl, dl; jne 0x7d20ea;  
		$rule2 = {29 d8 bb 01 00 00 00 75} 
		// sub eax, ebx; mov ebx, 1; jne 0x7d2128;  
		$rule3 = {48 c1 e0 08 8a 06 46 89 c5 b9 01 00 00 00 00 d2 75} 
		// dec eax; shl eax, 8; mov al, byte ptr [esi]; inc esi; mov ebp, eax; mov ecx, 1; add dl, dl; jne 0x7d213f;  
		$rule4 = {8a 16 46 10 d2 73} 
		// mov dl, byte ptr [esi]; inc esi; adc dl, dl; jae 0x7d206a;  
		$rule5 = {41 56 89 fe 29 c6 f3 a4 5e e9} 
		// inc ecx; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x7d2075;  
		$rule6 = {31 c0 00 d2 75} 
		// xor eax, eax; add dl, dl; jne 0x7d2096;  
		$rule7 = {56 89 fe 29 c6 f3 a4 5e e9} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x7d2075;  
		$rule8 = {11 c0 00 d2 75} 
		// adc eax, eax; add dl, dl; jne 0x7d20c6;  
		$rule9 = {57 89 c0 29 c7 8a 07 5f 88 07 47 bb 02 00 00 00 eb} 
		// push edi; mov eax, eax; sub edi, eax; mov al, byte ptr [edi]; pop edi; mov byte ptr [edi], al; inc edi; mov ebx, 2; jmp 0x7d2075;  
		$rule10 = {83 c1 02 56 89 fe 29 c6 f3 a4 5e e9} 
		// add ecx, 2; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x7d2075;  
		$rule11 = {8a 06 46 31 c9 c0 e8 01 74} 
		// mov al, byte ptr [esi]; inc esi; xor ecx, ecx; shr al, 1; je 0x7d219e;  
		$rule12 = {83 d1 02 89 c5 56 89 fe 29 c6 f3 a4 5e bb 01 00 00 00 e9} 
		// adc ecx, 2; mov ebp, eax; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, 1; jmp 0x7d2075;  
		$rule13 = {11 c9 00 d2 75} 
		// adc ecx, ecx; add dl, dl; jne 0x7d2119;  
		$rule14 = {b9 01 00 00 00 00 d2 75} 
		// mov ecx, 1; add dl, dl; jne 0x7d210e;  
		$rule15 = {56 89 fe 29 ee f3 a4 5e e9} 
		// push esi; mov esi, edi; sub esi, ebp; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x7d2075;  
		$rule16 = {88 07 47 bb 02 00 00 00 eb} 
		// mov byte ptr [edi], al; inc edi; mov ebx, 2; jmp 0x7d2075;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Themida_v304_protect_resources_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v304"
		configs="protect_resources_FISH_WHITE protect_application_FISH_WHITE"
	strings:
		$rule0 = {66 d1 eb e9} 
		// shr bx, 1; jmp 0x7c486d;  
		$rule1 = {fe ce e9} 
		// dec dh; jmp 0x7b7a9d;  
		$rule2 = {66 d1 d8 e9} 
		// rcr ax, 1; jmp 0x7b7a92;  
		$rule3 = {d3 20 e9} 
		// shl dword ptr [eax], cl; jmp 0x612926;  
		$rule4 = {31 c0 e9} 
		// xor eax, eax; jmp 0x71c0cc;  
		$rule5 = {31 db e9} 
		// xor ebx, ebx; jmp 0x739ce8;  
		$rule6 = {ac e9} 
		// lodsb al, byte ptr [esi]; jmp 0x7c1f80;  
		$rule7 = {4f e9} 
		// dec edi; jmp 0x7ad1cc;  
		$rule8 = {31 c1 e9} 
		// xor ecx, eax; jmp 0x7bde7a;  
		$rule9 = {88 d5 e9} 
		// mov ch, dl; jmp 0x7bda2d;  
		$rule10 = {88 f2 e9} 
		// mov dl, dh; jmp 0x7bd8de;  
		$rule11 = {31 da e9} 
		// xor edx, ebx; jmp 0x74fd48;  
		$rule12 = {30 c8 e9} 
		// xor al, cl; jmp 0x7c1f87;  
		$rule13 = {88 e9 e9} 
		// mov cl, ch; jmp 0x7bda26;  
		
	condition:
		pe.is_32bit() and (9 of them) and (pe.overlay.offset == 0 or for 6 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Themida_v237_memguard_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v237"
		configs="memguard_FISH_WHITE encrypt_application_FISH_WHITE delphi_bcb_FISH_WHITE encrypt_resources_FISH_WHITE full_FISH_WHITE_ENCODE protect_all_FISH_WHITE"
	strings:
		$rule0 = {31 06 01 1e 83 c6 04 49 eb} 
		// xor dword ptr [esi], eax; add dword ptr [esi], ebx; add esi, 4; dec ecx; jmp 0x5f705a;  
		$rule1 = {c6 03 00 bb 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 e8} 
		// mov byte ptr [ebx], 0; mov ebx, 0x1000; push 0x58680975; push 0x66b8d031; push ebx; push eax;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 1 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Themida_v237_protect_secureEngine_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v237"
		config="protect_secureEngine_FISH_WHITE"
	strings:
		$rule0 = {8a 01 41 84 c0 75} 
		// mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404625;  
		$rule1 = {31 06 01 1e 83 c6 04 49 eb} 
		// xor dword ptr [esi], eax; add dword ptr [esi], ebx; add esi, 4; dec ecx; jmp 0x5ed05a;  
		$rule2 = {89 75 d4 3b f3 74} 
		// mov dword ptr [ebp - 0x2c], esi; cmp esi, ebx; je 0x406055;  
		$rule3 = {8b 06 89 45 e0 ff 37 50 e8} 
		// mov eax, dword ptr [esi]; mov dword ptr [ebp - 0x20], eax; push dword ptr [edi]; push eax; call 0x4060cc;  
		$rule4 = {59 59 84 c0 74} 
		// pop ecx; pop ecx; test al, al; je 0x406050;  
		$rule5 = {8b ff 55 8b ec 8b 45 08 85 c0 74} 
		// mov edi, edi; push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 8]; test eax, eax; je 0x4060f7;  
		$rule6 = {32 c0 5d c3} 
		// xor al, al; pop ebp; ret ;  
		$rule7 = {88 84 05 fc fe ff ff 40 3b c7 72} 
		// mov byte ptr [ebp + eax - 0x104], al; inc eax; cmp eax, edi; jb 0x4088ad;  
		$rule8 = {c6 84 05 fc fe ff ff 20 40 3b c2 76} 
		// mov byte ptr [ebp + eax - 0x104], 0x20; inc eax; cmp eax, edx; jbe 0x4088d7;  
		$rule9 = {8b ff 55 8b ec 83 7d 08 00 74} 
		// mov edi, edi; push ebp; mov ebp, esp; cmp dword ptr [ebp + 8], 0; je 0x4059f3;  
		$rule10 = {8b ff 55 8b ec 53 57 8b f9 8b 4d 08 c6 47 0c 00 8d 5f 04 85 c9 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push ebx; push edi; mov edi, ecx; mov ecx, dword ptr [ebp + 8]; mov byte ptr [edi + 0xc], 0; lea ebx, [edi + 4]; test ecx, ecx; je 0x402f98;  
		$rule11 = {8b c7 5f 5b 5d } 
		// mov eax, edi; pop edi; pop ebx; pop ebp; ret 4;  
		$rule12 = {8b ff 55 8b ec 56 8b 75 08 85 f6 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push esi; mov esi, dword ptr [ebp + 8]; test esi, esi; je 0x405977;  
		$rule13 = {6a e0 33 d2 58 f7 f6 3b 45 0c 72} 
		// push -0x20; xor edx, edx; pop eax; div esi; cmp eax, dword ptr [ebp + 0xc]; jb 0x4059ab;  
		$rule14 = {0f af 75 0c 85 f6 75} 
		// imul esi, dword ptr [ebp + 0xc]; test esi, esi; jne 0x405996;  
		$rule15 = {5f 5b 5d c3} 
		// pop edi; pop ebx; pop ebp; ret ;  
		$rule16 = {42 8b ce 8d 79 01 8a 01 41 84 c0 75} 
		// inc edx; mov ecx, esi; lea edi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404625;  
		$rule17 = {2b cf 46 03 f1 8a 06 84 c0 75} 
		// sub ecx, edi; inc esi; add esi, ecx; mov al, byte ptr [esi]; test al, al; jne 0x40461b;  
		$rule18 = {8b cb 8d 71 01 8a 01 41 84 c0 75} 
		// mov ecx, ebx; lea esi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404654;  
		$rule19 = {2b ce 8d 41 01 89 45 f8 80 fa 3d 74} 
		// sub ecx, esi; lea eax, [ecx + 1]; mov dword ptr [ebp - 8], eax; cmp dl, 0x3d; je 0x40469f;  
		$rule20 = {6a 01 50 e8} 
		// push 1; push eax; call 0x40595e;  
		$rule21 = {83 c4 0c 85 c0 75} 
		// add esp, 0xc; test eax, eax; jne 0x4046c9;  
		$rule22 = {8b 45 fc 6a 00 89 30 83 c0 04 89 45 fc e8} 
		// mov eax, dword ptr [ebp - 4]; push 0; mov dword ptr [eax], esi; add eax, 4; mov dword ptr [ebp - 4], eax; call 0x4059bb;  
		$rule23 = {8b 45 f8 59 03 d8 8a 13 84 d2 75} 
		// mov eax, dword ptr [ebp - 8]; pop ecx; add ebx, eax; mov dl, byte ptr [ebx]; test dl, dl; jne 0x40464f;  
		$rule24 = {ff 03 85 f6 74} 
		// inc dword ptr [ebx]; test esi, esi; je 0x404408;  
		$rule25 = {59 85 c0 74} 
		// pop ecx; test eax, eax; je 0x404428;  
		$rule26 = {8a 45 fe 84 c0 74} 
		// mov al, byte ptr [ebp - 2]; test al, al; je 0x404448;  
		$rule27 = {8b ff 55 8b ec 83 ec 10 56 ff 75 08 8d 4d f0 e8} 
		// mov edi, edi; push ebp; mov ebp, esp; sub esp, 0x10; push esi; push dword ptr [ebp + 8]; lea ecx, [ebp - 0x10]; call 0x402f78;  
		$rule28 = {8a 4d ff 84 c9 75} 
		// mov cl, byte ptr [ebp - 1]; test cl, cl; jne 0x4043eb;  
		$rule29 = {83 4f f8 ff 80 67 0d f8 89 1f 8d 7f 38 89 5f cc 8d 47 e0 c7 47 d0 00 00 0a 0a c6 47 d4 0a 89 5f d6 88 5f da 3b c6 75} 
		// or dword ptr [edi - 8], 0xffffffff; and byte ptr [edi + 0xd], 0xf8; mov dword ptr [edi], ebx; lea edi, [edi + 0x38]; mov dword ptr [edi - 0x34], ebx; lea eax, [edi - 0x20]; mov dword ptr [edi - 0x30], 0xa0a0000; mov byte ptr [edi - 0x2c], 0xa; mov dword ptr [edi - 0x2a], ebx; mov byte ptr [edi - 0x26], bl; cmp eax, esi; jne 0x409530;  
		$rule30 = {53 68 a0 0f 00 00 8d 47 e0 50 e8} 
		// push ebx; push 0xfa0; lea eax, [edi - 0x20]; push eax; call 0x405d62;  
		$rule31 = {8a 07 88 06 46 8a 07 47 88 45 fe 0f be c0 50 e8} 
		// mov al, byte ptr [edi]; mov byte ptr [esi], al; inc esi; mov al, byte ptr [edi]; inc edi; mov byte ptr [ebp - 2], al; movsx eax, al; push eax; call 0x408ebe;  
		$rule32 = {8a 07 47 88 45 fe 0f be c0 50 e8} 
		// mov al, byte ptr [edi]; inc edi; mov byte ptr [ebp - 2], al; movsx eax, al; push eax; call 0x408ebe;  
		$rule33 = {42 89 30 8d 40 04 3b d1 75} 
		// inc edx; mov dword ptr [eax], esi; lea eax, [eax + 4]; cmp edx, ecx; jne 0x405e58;  
		$rule34 = {40 89 39 8d 49 04 3b c2 75} 
		// inc eax; mov dword ptr [ecx], edi; lea ecx, [ecx + 4]; cmp eax, edx; jne 0x404ecc;  
		
	condition:
		pe.is_32bit() and (24 of them) and (pe.overlay.offset == 0 or for 16 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Themida_v237_protect_application_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v237"
		config="protect_application_FISH_WHITE"
	strings:
		$rule0 = {50 30 04 0a 00 64 0a 01 c1 e8 10 30 44 0a 02 00 64 0a 03 58 83 e9 04 75} 
		// push eax; xor byte ptr [edx + ecx], al; add byte ptr [edx + ecx + 1], ah; shr eax, 0x10; xor byte ptr [edx + ecx + 2], al; add byte ptr [edx + ecx + 3], ah; pop eax; sub ecx, 4; jne 0x4a9dfb;  
		$rule1 = {fe 0f 47 49 75} 
		// dec byte ptr [edi]; inc edi; dec ecx; jne 0x41e940;  
		$rule2 = {8b 14 24 81 c4 04 00 00 00 e9} 
		// mov edx, dword ptr [esp]; add esp, 4; jmp 0x481e97;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Themida_v237_protect_resources_FISH_WHITE_combined
{
	meta:
		packer="Themida"
		generator="PackGenome"
		version="v237"
		config="protect_resources_FISH_WHITE"
	strings:
		$rule0 = {50 30 04 0a 00 64 0a 01 c1 e8 10 30 44 0a 02 00 64 0a 03 58 83 e9 04 75} 
		// push eax; xor byte ptr [edx + ecx], al; add byte ptr [edx + ecx + 1], ah; shr eax, 0x10; xor byte ptr [edx + ecx + 2], al; add byte ptr [edx + ecx + 3], ah; pop eax; sub ecx, 4; jne 0x499ce5;  
		$rule1 = {fe 0f 47 49 75} 
		// dec byte ptr [edi]; inc edi; dec ecx; jne 0x41e93c;  
		$rule2 = {fe c1 80 f9 0b 0f82} 
		// inc cl; cmp cl, 0xb; jb 0x49415f;  
		$rule3 = {0f b6 d9 55 e8} 
		// movzx ebx, cl; push ebp; call 0x494168;  
		$rule4 = {8a 01 41 84 c0 75} 
		// mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x404625;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// expressor
rule packer_expressor_v18_union_combined
{
	meta:
		packer="expressor"
		generator="PackGenome"
		version="v18"
		config="union"
	strings:
		$rule0 = {55 8b ec 8b 45 10 56 57 89 45 10 8b 75 0c 8b 7d 08 8b 4d 10 fc f3 a4 8b 45 08 5f 5e 5d c3} 
		// push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 0x10]; push esi; push edi; mov dword ptr [ebp + 0x10], eax; mov esi, dword ptr [ebp + 0xc]; mov edi, dword ptr [ebp + 8]; mov ecx, dword ptr [ebp + 0x10]; cld ; rep movsb byte ptr es:[edi], byte ptr [esi]; mov eax, dword ptr [ebp + 8]; pop edi; pop esi; pop ebp; ret ;  
		$rule1 = {8b 45 f0 83 38 00 0f84} 
		// mov eax, dword ptr [ebp - 0x10]; cmp dword ptr [eax], 0; je 0x427ae4;  
		$rule2 = {83 a5 98 fd ff ff 00 8b 45 f0 8b 00 25 00 00 00 80 74} 
		// and dword ptr [ebp - 0x268], 0; mov eax, dword ptr [ebp - 0x10]; mov eax, dword ptr [eax]; and eax, 0x80000000; je 0x427a60;  
		$rule3 = {8b 45 f0 8b 00 03 05 08 70 42 00 89 45 f8 8b 45 f8 40 40 50 ff b5 a4 fd ff ff ff} 
		// mov eax, dword ptr [ebp - 0x10]; mov eax, dword ptr [eax]; add eax, dword ptr [0x427008]; mov dword ptr [ebp - 8], eax; mov eax, dword ptr [ebp - 8]; inc eax; inc eax; push eax; push dword ptr [ebp - 0x25c]; call dword ptr [0x427038];  
		$rule4 = {6a 04 8d 85 98 fd ff ff 50 ff b5 d4 fd ff ff e8} 
		// push 4; lea eax, [ebp - 0x268]; push eax; push dword ptr [ebp - 0x22c]; call 0x427369;  
		$rule5 = {83 c4 0c 8b 45 f0 83 c0 04 89 45 f0 8b 85 d4 fd ff ff 83 c0 04 89 85 d4 fd ff ff e9} 
		// add esp, 0xc; mov eax, dword ptr [ebp - 0x10]; add eax, 4; mov dword ptr [ebp - 0x10], eax; mov eax, dword ptr [ebp - 0x22c]; add eax, 4; mov dword ptr [ebp - 0x22c], eax; jmp 0x427a1f;  
		$rule6 = {8b 85 ac fd ff ff 0f be 00 83 f8 5c 74} 
		// mov eax, dword ptr [ebp - 0x254]; movsx eax, byte ptr [eax]; cmp eax, 0x5c; je 0x4274de;  
		$rule7 = {8b 85 ac fd ff ff 48 89 85 ac fd ff ff eb} 
		// mov eax, dword ptr [ebp - 0x254]; dec eax; mov dword ptr [ebp - 0x254], eax; jmp 0x4274c1;  
		$rule8 = {8b 85 a8 fd ff ff 40 89 85 a8 fd ff ff a1 04 70 42 00 0f b7 80 a4 00 00 00 39 85 a8 fd ff ff 0f8d} 
		// mov eax, dword ptr [ebp - 0x258]; inc eax; mov dword ptr [ebp - 0x258], eax; mov eax, dword ptr [0x427004]; movzx eax, word ptr [eax + 0xa4]; cmp dword ptr [ebp - 0x258], eax; jge 0x42771c;  
		$rule9 = {83 a5 90 fd ff ff 00 8b 85 90 fd ff ff 89 85 a0 fd ff ff 83 bd a0 fd ff ff 00 75} 
		// and dword ptr [ebp - 0x270], 0; mov eax, dword ptr [ebp - 0x270]; mov dword ptr [ebp - 0x260], eax; cmp dword ptr [ebp - 0x260], 0; jne 0x4276f5;  
		$rule10 = {8b 85 a8 fd ff ff 6b c0 18 8b 0d 04 70 42 00 ff b4 01 b0 00 00 00 ff b5 bc fd ff ff 8b 85 a8 fd ff ff 6b c0 18 8b 0d 04 70 42 00 8b 15 08 70 42 00 03 94 01 b4 00 00 00 52 e8} 
		// mov eax, dword ptr [ebp - 0x258]; imul eax, eax, 0x18; mov ecx, dword ptr [0x427004]; push dword ptr [ecx + eax + 0xb0]; push dword ptr [ebp - 0x244]; mov eax, dword ptr [ebp - 0x258]; imul eax, eax, 0x18; mov ecx, dword ptr [0x427004]; mov edx, dword ptr [0x427008]; add edx, dword ptr [ecx + eax + 0xb4]; push edx; call 0x427369;  
		$rule11 = {83 c4 0c 8b 85 a8 fd ff ff 6b c0 18 8b 0d 04 70 42 00 8b 95 bc fd ff ff 03 94 01 b0 00 00 00 89 95 bc fd ff ff e9} 
		// add esp, 0xc; mov eax, dword ptr [ebp - 0x258]; imul eax, eax, 0x18; mov ecx, dword ptr [0x427004]; mov edx, dword ptr [ebp - 0x244]; add edx, dword ptr [ecx + eax + 0xb0]; mov dword ptr [ebp - 0x244], edx; jmp 0x427632;  
		$rule12 = {8b 0d 04 70 42 00 b8 42 74 42 00 2b 41 74 c3} 
		// mov ecx, dword ptr [0x427004]; mov eax, 0x427442; sub eax, dword ptr [ecx + 0x74]; ret ;  
		$rule13 = {55 8b ec 81 ec 84 02 00 00 53 56 57 83 a5 a8 fd ff ff 00 } 
		// push ebp; mov ebp, esp; sub esp, 0x284; push ebx; push esi; push edi; and dword ptr [ebp - 0x258], 0; jmp 0x427464;  
		$rule14 = {a1 00 70 42 00 05 00 70 42 00 a3 04 70 42 00 a1 04 70 42 00 83 78 70 00 75} 
		// mov eax, dword ptr [0x427000]; add eax, 0x427000; mov dword ptr [0x427004], eax; mov eax, dword ptr [0x427004]; cmp dword ptr [eax + 0x70], 0; jne 0x427492;  
		$rule15 = {a3 08 70 42 00 68 04 01 00 00 8d 85 d8 fd ff ff 50 ff 35 14 70 42 00 ff} 
		// mov dword ptr [0x427008], eax; push 0x104; lea eax, [ebp - 0x228]; push eax; push dword ptr [0x427014]; call dword ptr [0x427048];  
		$rule16 = {8d 84 05 d7 fd ff ff 89 85 ac fd ff ff 8b 85 ac fd ff ff 0f be 00 83 f8 5c 74} 
		// lea eax, [ebp + eax - 0x229]; mov dword ptr [ebp - 0x254], eax; mov eax, dword ptr [ebp - 0x254]; movsx eax, byte ptr [eax]; cmp eax, 0x5c; je 0x4274de;  
		$rule17 = {8b 85 ac fd ff ff 40 89 85 ac fd ff ff 8b 85 ac fd ff ff 8d 8d d8 fd ff ff 2b c1 89 45 f4 ff 75 f4 8d 85 d8 fd ff ff 50 8d 85 e8 fe ff ff 50 e8} 
		// mov eax, dword ptr [ebp - 0x254]; inc eax; mov dword ptr [ebp - 0x254], eax; mov eax, dword ptr [ebp - 0x254]; lea ecx, [ebp - 0x228]; sub eax, ecx; mov dword ptr [ebp - 0xc], eax; push dword ptr [ebp - 0xc]; lea eax, [ebp - 0x228]; push eax; lea eax, [ebp - 0x118]; push eax; call 0x427369;  
		$rule18 = {a1 04 70 42 00 0f b7 80 a4 00 00 00 39 85 a8 fd ff ff 0f8d} 
		// mov eax, dword ptr [0x427004]; movzx eax, word ptr [eax + 0xa4]; cmp dword ptr [ebp - 0x258], eax; jge 0x42771c;  
		$rule19 = {68 00 80 00 00 6a 00 ff 75 fc ff} 
		// push 0x8000; push 0; push dword ptr [ebp - 4]; call dword ptr [0x427024];  
		$rule20 = {a1 04 70 42 00 8b 0d 08 70 42 00 03 88 84 00 00 00 89 8d b4 fd ff ff 8b 85 b4 fd ff ff 83 78 0c 00 0f84} 
		// mov eax, dword ptr [0x427004]; mov ecx, dword ptr [0x427008]; add ecx, dword ptr [eax + 0x84]; mov dword ptr [ebp - 0x24c], ecx; mov eax, dword ptr [ebp - 0x24c]; cmp dword ptr [eax + 0xc], 0; je 0x427af8;  
		$rule21 = {8b 85 b4 fd ff ff 83 78 0c 00 0f84} 
		// mov eax, dword ptr [ebp - 0x24c]; cmp dword ptr [eax + 0xc], 0; je 0x427af8;  
		$rule22 = {a1 04 70 42 00 83 b8 84 00 00 00 00 0f84} 
		// mov eax, dword ptr [0x427004]; cmp dword ptr [eax + 0x84], 0; je 0x427af8;  
		$rule23 = {8d 85 c0 fd ff ff 50 6a 40 6a 14 ff b5 b4 fd ff ff ff} 
		// lea eax, [ebp - 0x240]; push eax; push 0x40; push 0x14; push dword ptr [ebp - 0x24c]; call dword ptr [0x427044];  
		$rule24 = {89 85 a4 fd ff ff 83 bd a4 fd ff ff 00 75} 
		// mov dword ptr [ebp - 0x25c], eax; cmp dword ptr [ebp - 0x25c], 0; jne 0x427949;  
		$rule25 = {8b 85 b4 fd ff ff 8b 0d 08 70 42 00 03 48 10 89 8d d4 fd ff ff 8b 85 b4 fd ff ff 83 38 00 75} 
		// mov eax, dword ptr [ebp - 0x24c]; mov ecx, dword ptr [0x427008]; add ecx, dword ptr [eax + 0x10]; mov dword ptr [ebp - 0x22c], ecx; mov eax, dword ptr [ebp - 0x24c]; cmp dword ptr [eax], 0; jne 0x427a0e;  
		$rule26 = {8b 85 b4 fd ff ff 8b 0d 08 70 42 00 03 08 89 4d f0 8b 45 f0 83 38 00 0f84} 
		// mov eax, dword ptr [ebp - 0x24c]; mov ecx, dword ptr [0x427008]; add ecx, dword ptr [eax]; mov dword ptr [ebp - 0x10], ecx; mov eax, dword ptr [ebp - 0x10]; cmp dword ptr [eax], 0; je 0x427ae4;  
		$rule27 = {8b 85 b4 fd ff ff 83 c0 14 89 85 b4 fd ff ff e9} 
		// mov eax, dword ptr [ebp - 0x24c]; add eax, 0x14; mov dword ptr [ebp - 0x24c], eax; jmp 0x4278ca;  
		$rule28 = {a1 04 70 42 00 8b 0d 08 70 42 00 03 48 6c 89 0d 1c 70 42 00 8d 85 c0 fd ff ff 50 6a 40 68 00 10 00 00 ff 35 08 70 42 00 ff} 
		// mov eax, dword ptr [0x427004]; mov ecx, dword ptr [0x427008]; add ecx, dword ptr [eax + 0x6c]; mov dword ptr [0x42701c], ecx; lea eax, [ebp - 0x240]; push eax; push 0x40; push 0x1000; push dword ptr [0x427008]; call dword ptr [0x427044];  
		$rule29 = {8b 85 b0 fd ff ff 0f b7 40 14 8b 8d b0 fd ff ff 8d 44 01 18 89 85 b8 fd ff ff 8b 85 b8 fd ff ff 8b 40 24 25 00 00 00 80 74} 
		// mov eax, dword ptr [ebp - 0x250]; movzx eax, word ptr [eax + 0x14]; mov ecx, dword ptr [ebp - 0x250]; lea eax, [ecx + eax + 0x18]; mov dword ptr [ebp - 0x248], eax; mov eax, dword ptr [ebp - 0x248]; mov eax, dword ptr [eax + 0x24]; and eax, 0x80000000; je 0x427b75;  
		$rule30 = {8b 85 b8 fd ff ff 83 c0 24 89 85 94 fd ff ff 8b 85 b8 fd ff ff 8b 40 24 2d 00 00 00 80 8b 8d 94 fd ff ff 89 01 6a 00 ff b5 c0 fd ff ff 68 00 10 00 00 ff 35 08 70 42 00 ff} 
		// mov eax, dword ptr [ebp - 0x248]; add eax, 0x24; mov dword ptr [ebp - 0x26c], eax; mov eax, dword ptr [ebp - 0x248]; mov eax, dword ptr [eax + 0x24]; sub eax, 0x80000000; mov ecx, dword ptr [ebp - 0x26c]; mov dword ptr [ecx], eax; push 0; push dword ptr [ebp - 0x240]; push 0x1000; push dword ptr [0x427008]; call dword ptr [0x427044];  
		
	condition:
		pe.is_32bit() and (21 of them) and (pe.overlay.offset == 0 or for 14 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_expressor_v18_default_combined
{
	meta:
		packer="expressor"
		generator="PackGenome"
		version="v18"
		configs="default level3 export noresources winloader"
	strings:
		$rule0 = {8b 4c 24 04 0f b7 11 56 8b 74 24 0c 8b 46 08 57 8b f8 c1 ef 0b 0f af fa 8b 56 0c 3b d7 73} 
		// mov ecx, dword ptr [esp + 4]; movzx edx, word ptr [ecx]; push esi; mov esi, dword ptr [esp + 0xc]; mov eax, dword ptr [esi + 8]; push edi; mov edi, eax; shr edi, 0xb; imul edi, edx; mov edx, dword ptr [esi + 0xc]; cmp edx, edi; jae 0x427e11;  
		$rule1 = {89 7e 08 0f b7 01 0f b7 d0 bf 00 08 00 00 2b fa c1 ff 05 03 f8 66 89 39 81 7e 08 00 00 00 01 73} 
		// mov dword ptr [esi + 8], edi; movzx eax, word ptr [ecx]; movzx edx, ax; mov edi, 0x800; sub edi, edx; sar edi, 5; add edi, eax; mov word ptr [ecx], di; cmp dword ptr [esi + 8], 0x1000000; jae 0x427e0d;  
		$rule2 = {5f 5e c3} 
		// pop edi; pop esi; ret ;  
		$rule3 = {2b c7 2b d7 89 46 08 89 56 0c 0f b7 01 66 8b d0 66 c1 ea 05 66 2b c2 66 89 01 81 7e 08 00 00 00 01 73} 
		// sub eax, edi; sub edx, edi; mov dword ptr [esi + 8], eax; mov dword ptr [esi + 0xc], edx; movzx eax, word ptr [ecx]; mov dx, ax; shr dx, 5; sub ax, dx; mov word ptr [ecx], ax; cmp dword ptr [esi + 8], 0x1000000; jae 0x427e4d;  
		$rule4 = {33 c0 40 5f 5e c3} 
		// xor eax, eax; inc eax; pop edi; pop esi; ret ;  
		$rule5 = {0b c6 3d 00 01 00 00 59 59 7c} 
		// or eax, esi; cmp eax, 0x100; pop ecx; pop ecx; jl 0x427ec9;  
		$rule6 = {ff 74 24 0c 8d 34 00 8b 44 24 0c 03 c6 50 e8} 
		// push dword ptr [esp + 0xc]; lea esi, [eax + eax]; mov eax, dword ptr [esp + 0xc]; add eax, esi; push eax; call 0x427db4;  
		$rule7 = {03 c6 4f 85 ff 59 59 7f} 
		// add eax, esi; dec edi; test edi, edi; pop ecx; pop ecx; jg 0x427e62;  
		$rule8 = {8a 0c 38 80 f9 e8 74} 
		// mov cl, byte ptr [eax + edi]; cmp cl, 0xe8; je 0x427c1c;  
		$rule9 = {ff 75 10 8d 34 00 8b 45 08 03 c6 50 e8} 
		// push dword ptr [ebp + 0x10]; lea esi, [eax + eax]; mov eax, dword ptr [ebp + 8]; add eax, esi; push eax; call 0x427db4;  
		$rule10 = {8a 18 88 1c 39 41 40 4a 85 d2 89 4d 14 7e} 
		// mov bl, byte ptr [eax]; mov byte ptr [ecx + edi], bl; inc ecx; inc eax; dec edx; test edx, edx; mov dword ptr [ebp + 0x14], ecx; jle 0x4282fa;  
		$rule11 = {8b 45 08 ff 75 0c 8d 34 1b 03 c6 50 e8} 
		// mov eax, dword ptr [ebp + 8]; push dword ptr [ebp + 0xc]; lea esi, [ebx + ebx]; add eax, esi; push eax; call 0x427db4;  
		$rule12 = {59 0b c6 59 8b d8 3b df 7c} 
		// pop ecx; or eax, esi; pop ecx; mov ebx, eax; cmp ebx, edi; jl 0x427f28;  
		$rule13 = {8b 54 24 04 8b 0a 3b 4a 04 75} 
		// mov edx, dword ptr [esp + 4]; mov ecx, dword ptr [edx]; cmp ecx, dword ptr [edx + 4]; jne 0x427d51;  
		$rule14 = {8a 01 41 89 0a c3} 
		// mov al, byte ptr [ecx]; inc ecx; mov dword ptr [edx], ecx; ret ;  
		$rule15 = {8b 7d f8 8b 45 e4 23 45 14 8d 4d cc 51 8b cf c1 e1 04 03 c8 89 45 18 8d 04 4e 50 e8} 
		// mov edi, dword ptr [ebp - 8]; mov eax, dword ptr [ebp - 0x1c]; and eax, dword ptr [ebp + 0x14]; lea ecx, [ebp - 0x34]; push ecx; mov ecx, edi; shl ecx, 4; add ecx, eax; mov dword ptr [ebp + 0x18], eax; lea eax, [esi + ecx*2]; push eax; call 0x427db4;  
		$rule16 = {85 c0 59 59 0f85} 
		// test eax, eax; pop ecx; pop ecx; jne 0x42811f;  
		$rule17 = {8b 45 14 3b 45 28 0f82} 
		// mov eax, dword ptr [ebp + 0x14]; cmp eax, dword ptr [ebp + 0x28]; jb 0x42806b;  
		$rule18 = {03 db 59 0b d8 3b f0 59 75} 
		// add ebx, ebx; pop ecx; or ebx, eax; cmp esi, eax; pop ecx; jne 0x427f3f;  
		$rule19 = {59 59 8b cf 8d 14 06 d3 e0 0b d8 47 3b 7c 24 14 7c} 
		// pop ecx; pop ecx; mov ecx, edi; lea edx, [esi + eax]; shl eax, cl; or ebx, eax; inc edi; cmp edi, dword ptr [esp + 0x14]; jl 0x427e9a;  
		$rule20 = {d1 65 08 d1 ef 3b df 72} 
		// shl dword ptr [ebp + 8], 1; shr edi, 1; cmp ebx, edi; jb 0x427d83;  
		$rule21 = {ff 4d 0c 83 7d 0c 00 7f} 
		// dec dword ptr [ebp + 0xc]; cmp dword ptr [ebp + 0xc], 0; jg 0x427d74;  
		$rule22 = {0f b6 75 10 8b 4d 08 ff 75 0c d0 65 10 c1 ee 07 8d 46 01 c1 e0 08 03 c3 8d 04 41 50 e8} 
		// movzx esi, byte ptr [ebp + 0x10]; mov ecx, dword ptr [ebp + 8]; push dword ptr [ebp + 0xc]; shl byte ptr [ebp + 0x10], 1; shr esi, 7; lea eax, [esi + 1]; shl eax, 8; add eax, ebx; lea eax, [ecx + eax*2]; push eax; call 0x427db4;  
		$rule23 = {8b 55 e0 23 55 14 6a 08 59 2a 4d 10 0f b6 c3 d3 e8 8b 4d 10 d3 e2 03 c2 69 c0 00 06 00 00 83 ff 04 8d 84 30 6c 0e 00 00 7d} 
		// mov edx, dword ptr [ebp - 0x20]; and edx, dword ptr [ebp + 0x14]; push 8; pop ecx; sub cl, byte ptr [ebp + 0x10]; movzx eax, bl; shr eax, cl; mov ecx, dword ptr [ebp + 0x10]; shl edx, cl; add eax, edx; imul eax, eax, 0x600; cmp edi, 4; lea eax, [eax + esi + 0xe6c]; jge 0x4280c5;  
		$rule24 = {8b 44 24 10 ff 74 24 18 8d 34 12 03 c6 50 e8} 
		// mov eax, dword ptr [esp + 0x10]; push dword ptr [esp + 0x18]; lea esi, [edx + edx]; add eax, esi; push eax; call 0x427db4;  
		$rule25 = {55 8b ec 33 c0 57 8b 7d 0c 40 85 ff 7e} 
		// push ebp; mov ebp, esp; xor eax, eax; push edi; mov edi, dword ptr [ebp + 0xc]; inc eax; test edi, edi; jle 0x427e7d;  
		$rule26 = {56 ff 75 10 8d 34 00 8b 45 08 03 c6 50 e8} 
		// push esi; push dword ptr [ebp + 0x10]; lea esi, [eax + eax]; mov eax, dword ptr [ebp + 8]; add eax, esi; push eax; call 0x427db4;  
		$rule27 = {5e 8b 4d 0c 33 d2 42 d3 e2 5f 2b c2 5d c3} 
		// pop esi; mov ecx, dword ptr [ebp + 0xc]; xor edx, edx; inc edx; shl edx, cl; pop edi; sub eax, edx; pop ebp; ret ;  
		$rule28 = {59 8b 4e 0c 0f b6 c0 c1 e1 08 0b c1 c1 66 08 08 89 46 0c 33 c0 eb} 
		// pop ecx; mov ecx, dword ptr [esi + 0xc]; movzx eax, al; shl ecx, 8; or eax, ecx; shl dword ptr [esi + 8], 8; mov dword ptr [esi + 0xc], eax; xor eax, eax; jmp 0x427e50;  
		$rule29 = {33 c0 40 56 ff 74 24 0c 8d 34 00 8b 44 24 0c 03 c6 50 e8} 
		// xor eax, eax; inc eax; push esi; push dword ptr [esp + 0xc]; lea esi, [eax + eax]; mov eax, dword ptr [esp + 0xc]; add eax, esi; push eax; call 0x427db4;  
		$rule30 = {8d 4d cc 51 50 e8} 
		// lea ecx, [ebp - 0x34]; push ecx; push eax; call 0x427ec5;  
		$rule31 = {59 59 8a d8 8b 45 24 8b 4d 14 ff 45 14 88 1c 01 e9} 
		// pop ecx; pop ecx; mov bl, al; mov eax, dword ptr [ebp + 0x24]; mov ecx, dword ptr [ebp + 0x14]; inc dword ptr [ebp + 0x14]; mov byte ptr [ecx + eax], bl; jmp 0x4282fa;  
		$rule32 = {2b df 83 4d 08 01 81 ff 00 00 00 01 73} 
		// sub ebx, edi; or dword ptr [ebp + 8], 1; cmp edi, 0x1000000; jae 0x427d9d;  
		$rule33 = {8d 45 cc 50 33 db 8d 84 7e 80 01 00 00 43 50 89 5d ec e8} 
		// lea eax, [ebp - 0x34]; push eax; xor ebx, ebx; lea eax, [esi + edi*2 + 0x180]; inc ebx; push eax; mov dword ptr [ebp - 0x14], ebx; call 0x427db4;  
		$rule34 = {3b c3 59 59 0f85} 
		// cmp eax, ebx; pop ecx; pop ecx; jne 0x428209;  
		$rule35 = {56 8b 74 24 08 57 8b 7c 24 10 57 56 e8} 
		// push esi; mov esi, dword ptr [esp + 8]; push edi; mov edi, dword ptr [esp + 0x10]; push edi; push esi; call 0x427db4;  
		$rule36 = {85 c0 59 59 57 75} 
		// test eax, eax; pop ecx; pop ecx; push edi; jne 0x427f7a;  
		$rule37 = {8b 4d 14 8b 7d 24 8b c1 2b 45 fc 42 42 03 c7 8a 18 88 1c 39 41 40 4a 85 d2 89 4d 14 7e} 
		// mov ecx, dword ptr [ebp + 0x14]; mov edi, dword ptr [ebp + 0x24]; mov eax, ecx; sub eax, dword ptr [ebp - 4]; inc edx; inc edx; add eax, edi; mov bl, byte ptr [eax]; mov byte ptr [ecx + edi], bl; inc ecx; inc eax; dec edx; test edx, edx; mov dword ptr [ebp + 0x14], ecx; jle 0x4282fa;  
		$rule38 = {89 7d f8 83 7d ec 00 74} 
		// mov dword ptr [ebp - 8], edi; cmp dword ptr [ebp - 0x14], 0; je 0x428100;  
		$rule39 = {8b 44 24 18 c1 e0 04 8d 44 30 04 6a 03 50 e8} 
		// mov eax, dword ptr [esp + 0x18]; shl eax, 4; lea eax, [eax + esi + 4]; push 3; push eax; call 0x427e53;  
		$rule40 = {55 8b ec 53 56 33 db 57 43 bf 00 01 00 00 0f b6 75 10 8b 4d 08 ff 75 0c d0 65 10 c1 ee 07 8d 46 01 c1 e0 08 03 c3 8d 04 41 50 e8} 
		// push ebp; mov ebp, esp; push ebx; push esi; xor ebx, ebx; push edi; inc ebx; mov edi, 0x100; movzx esi, byte ptr [ebp + 0x10]; mov ecx, dword ptr [ebp + 8]; push dword ptr [ebp + 0xc]; shl byte ptr [ebp + 0x10], 1; shr esi, 7; lea eax, [esi + 1]; shl eax, 8; add eax, ebx; lea eax, [ecx + eax*2]; push eax; call 0x427db4;  
		$rule41 = {5f 5e 8a c3 5b 5d c3} 
		// pop edi; pop esi; mov al, bl; pop ebx; pop ebp; ret ;  
		$rule42 = {8b 4d 14 2b 4d fc 8b 55 24 8a 0c 11 88 4d 08 ff 75 08 8d 4d cc 51 50 e8} 
		// mov ecx, dword ptr [ebp + 0x14]; sub ecx, dword ptr [ebp - 4]; mov edx, dword ptr [ebp + 0x24]; mov cl, byte ptr [ecx + edx]; mov byte ptr [ebp + 8], cl; push dword ptr [ebp + 8]; lea ecx, [ebp - 0x34]; push ecx; push eax; call 0x427ee9;  
		$rule43 = {83 c4 0c 83 65 ec 00 eb} 
		// add esp, 0xc; and dword ptr [ebp - 0x14], 0; jmp 0x42810c;  
		$rule44 = {8a d8 8b 45 24 8b 4d 14 ff 45 14 88 1c 01 e9} 
		// mov bl, al; mov eax, dword ptr [ebp + 0x24]; mov ecx, dword ptr [ebp + 0x14]; inc dword ptr [ebp + 0x14]; mov byte ptr [ecx + eax], bl; jmp 0x4282fa;  
		$rule45 = {8b 45 f4 89 45 e8 8b 45 f0 ff 75 18 89 45 f4 8b 45 fc 89 45 f0 33 c0 83 ff 07 0f 9d c0 48 83 e0 fd 83 c0 0a 89 45 f8 8d 45 cc 50 8d 86 64 06 00 00 50 e8} 
		// mov eax, dword ptr [ebp - 0xc]; mov dword ptr [ebp - 0x18], eax; mov eax, dword ptr [ebp - 0x10]; push dword ptr [ebp + 0x18]; mov dword ptr [ebp - 0xc], eax; mov eax, dword ptr [ebp - 4]; mov dword ptr [ebp - 0x10], eax; xor eax, eax; cmp edi, 7; setge al; dec eax; and eax, 0xfffffffd; add eax, 0xa; mov dword ptr [ebp - 8], eax; lea eax, [ebp - 0x34]; push eax; lea eax, [esi + 0x664]; push eax; call 0x427f4a;  
		$rule46 = {83 c4 0c 83 f8 04 89 45 18 7c} 
		// add esp, 0xc; cmp eax, 4; mov dword ptr [ebp + 0x18], eax; jl 0x42824e;  
		$rule47 = {83 c4 0c 83 f8 04 7c} 
		// add esp, 0xc; cmp eax, 4; jl 0x4282c5;  
		$rule48 = {53 33 d2 57 33 db 42 33 ff 39 5c 24 10 7e} 
		// push ebx; xor edx, edx; push edi; xor ebx, ebx; inc edx; xor edi, edi; cmp dword ptr [esp + 0x10], ebx; jle 0x427ec0;  
		$rule49 = {56 8b 44 24 10 ff 74 24 18 8d 34 12 03 c6 50 e8} 
		// push esi; mov eax, dword ptr [esp + 0x10]; push dword ptr [esp + 0x18]; lea esi, [edx + edx]; add eax, esi; push eax; call 0x427db4;  
		$rule50 = {5e 5f 8b c3 5b c3} 
		// pop esi; pop edi; mov eax, ebx; pop ebx; ret ;  
		$rule51 = {8b c8 8b f8 23 fb d1 f9 49 83 cf 02 d3 e7 83 f8 0e 7d} 
		// mov ecx, eax; mov edi, eax; and edi, ebx; sar ecx, 1; dec ecx; or edi, 2; shl edi, cl; cmp eax, 0xe; jge 0x42829a;  
		$rule52 = {8b 55 18 47 89 7d fc 83 7d fc 00 74} 
		// mov edx, dword ptr [ebp + 0x18]; inc edi; mov dword ptr [ebp - 4], edi; cmp dword ptr [ebp - 4], 0; je 0x428306;  
		$rule53 = {8d 4d cc 51 c1 e0 07 8d 84 30 60 03 00 00 6a 06 50 e8} 
		// lea ecx, [ebp - 0x34]; push ecx; shl eax, 7; lea eax, [eax + esi + 0x360]; push 6; push eax; call 0x427e53;  
		$rule54 = {55 8b ec 8b 45 0c 53 56 8b 75 08 83 65 08 00 85 c0 8b 5e 0c 57 8b 7e 08 89 45 0c 7e} 
		// push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 0xc]; push ebx; push esi; mov esi, dword ptr [ebp + 8]; and dword ptr [ebp + 8], 0; test eax, eax; mov ebx, dword ptr [esi + 0xc]; push edi; mov edi, dword ptr [esi + 8]; mov dword ptr [ebp + 0xc], eax; jle 0x427da6;  
		$rule55 = {8b 45 08 89 7e 08 5f 89 5e 0c 5e 5b 5d c3} 
		// mov eax, dword ptr [ebp + 8]; mov dword ptr [esi + 8], edi; pop edi; mov dword ptr [esi + 0xc], ebx; pop esi; pop ebx; pop ebp; ret ;  
		$rule56 = {83 c1 fc 51 8d 45 cc 50 e8} 
		// add ecx, -4; push ecx; lea eax, [ebp - 0x34]; push eax; call 0x427d57;  
		$rule57 = {c1 e0 04 03 f8 8d 45 cc 50 8d 86 44 06 00 00 6a 04 50 e8} 
		// shl eax, 4; add edi, eax; lea eax, [ebp - 0x34]; push eax; lea eax, [esi + 0x644]; push 4; push eax; call 0x427e8a;  
		$rule58 = {83 c4 14 03 f8 eb} 
		// add esp, 0x14; add edi, eax; jmp 0x4282ca;  
		$rule59 = {8d 45 cc 50 8d 84 7e 98 01 00 00 50 e8} 
		// lea eax, [ebp - 0x34]; push eax; lea eax, [esi + edi*2 + 0x198]; push eax; call 0x427db4;  
		$rule60 = {59 85 c0 59 8d 45 cc 50 75} 
		// pop ecx; test eax, eax; pop ecx; lea eax, [ebp - 0x34]; push eax; jne 0x42818e;  
		$rule61 = {8d 47 0f c1 e0 04 03 45 18 8d 04 46 50 e8} 
		// lea eax, [edi + 0xf]; shl eax, 4; add eax, dword ptr [ebp + 0x18]; lea eax, [esi + eax*2]; push eax; call 0x427db4;  
		$rule62 = {8b d0 33 c0 83 c4 0c 83 ff 07 0f 9d c0 48 83 e0 fd 83 c0 0b 89 45 f8 e9} 
		// mov edx, eax; xor eax, eax; add esp, 0xc; cmp edi, 7; setge al; dec eax; and eax, 0xfffffffd; add eax, 0xb; mov dword ptr [ebp - 8], eax; jmp 0x4282d1;  
		$rule63 = {56 c1 e7 08 e8} 
		// push esi; shl edi, 8; call 0x427d3c;  
		$rule64 = {0f b6 c0 c1 e3 08 59 0b d8 ff 4d 0c 83 7d 0c 00 7f} 
		// movzx eax, al; shl ebx, 8; pop ecx; or ebx, eax; dec dword ptr [ebp + 0xc]; cmp dword ptr [ebp + 0xc], 0; jg 0x427d74;  
		$rule65 = {ff 75 18 8d 45 cc 50 8d 86 68 0a 00 00 50 e8} 
		// push dword ptr [ebp + 0x18]; lea eax, [ebp - 0x34]; push eax; lea eax, [esi + 0xa68]; push eax; call 0x427f4a;  
		
	condition:
		pe.is_32bit() and (46 of them) and (pe.overlay.offset == 0 or for 32 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// mpress
rule packer_mpress_v218
{
	meta:
		packer="mpress"
		generator="PackGenome"
		versions="v218 v219"
	strings:
		$rule0 = {8d 14 36 8b 6c 24 14 03 ea 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; add ebp, edx; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b3e6;  
		$rule1 = {8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 3b f8 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41b414;  
		$rule2 = {8b d9 ac 41 24 fe 3c e8 75} 
		// mov ebx, ecx; lodsb al, byte ptr [esi]; inc ecx; and al, 0xfe; cmp al, 0xe8; jne 0x41b0f5;  
		$rule3 = {89 44 24 48 b8 00 08 00 00 2b c6 8b f2 c1 f8 05 8d 04 08 66 89 45 00 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; lea eax, [eax + ecx]; mov word ptr [ebp], ax; jmp 0x41b3b3;  
		$rule4 = {29 44 24 48 2b f8 8b c1 8d 72 01 66 c1 e8 05 66 2b c8 66 89 4d 00 eb} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; mov word ptr [ebp], cx; jmp 0x41b3b3;  
		$rule5 = {8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41bb75;  
		$rule6 = {8b ac 24 a4 00 00 00 39 6c 24 74 72} 
		// mov ebp, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], ebp; jb 0x41bb55;  
		$rule7 = {8d 2c 00 8b 74 24 08 03 f5 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b9a0;  
		$rule8 = {49 8a 44 39 06 88 04 31 75} 
		// dec ecx; mov al, byte ptr [ecx + edi + 6]; mov byte ptr [ecx + esi], al; jne 0x41b096;  
		$rule9 = {8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 3b f8 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41b905;  
		$rule10 = {8b 74 24 74 23 74 24 6c 8b 44 24 60 8b 54 24 78 c1 e0 04 89 74 24 44 03 c6 81 7c 24 48 ff ff ff 00 8d 2c 42 77} 
		// mov esi, dword ptr [esp + 0x74]; and esi, dword ptr [esp + 0x6c]; mov eax, dword ptr [esp + 0x60]; mov edx, dword ptr [esp + 0x78]; shl eax, 4; mov dword ptr [esp + 0x44], esi; add eax, esi; cmp dword ptr [esp + 0x48], 0xffffff; lea ebp, [edx + eax*2]; ja 0x41b27e;  
		$rule11 = {8b 84 24 a4 00 00 00 39 44 24 74 0f82} 
		// mov eax, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], eax; jb 0x41b240;  
		$rule12 = {8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 3b f8 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41b385;  
		$rule13 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 ca 0f af c1 3b f8 0f83} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41b474;  
		$rule14 = {89 44 24 48 b8 00 08 00 00 2b c1 c1 f8 05 8d 04 10 66 89 06 8b c5 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [eax + edx]; mov word ptr [esi], ax; mov eax, ebp; jmp 0x41b9e1;  
		$rule15 = {8b 6c 24 24 4d 89 6c 24 24 75} 
		// mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41b975;  
		$rule16 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 f2 0f af c6 3b f8 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx esi, dx; imul eax, esi; cmp edi, eax; jae 0x41baf0;  
		$rule17 = {8d 2c 12 8b 74 24 10 03 f5 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b8d9;  
		$rule18 = {d1 6c 24 48 03 f6 3b 7c 24 48 72} 
		// shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41ba67;  
		$rule19 = {89 44 24 48 b8 00 08 00 00 2b c1 c1 f8 05 8d 04 10 8b d5 66 89 06 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [eax + edx]; mov edx, ebp; mov word ptr [esi], ax; jmp 0x41b91a;  
		$rule20 = {8b 74 24 28 4e 89 74 24 28 75} 
		// mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41b8ae;  
		$rule21 = {d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 02 77} 
		// shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [edx + eax]; ja 0x41b34a;  
		$rule22 = {8b 6c 24 04 03 c0 89 44 24 18 03 e8 81 7c 24 48 ff ff ff 00 77} 
		// mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41bac0;  
		$rule23 = {89 44 24 48 b8 00 08 00 00 2b c1 8a 4c 24 64 c1 f8 05 be 01 00 00 00 8d 04 10 0f b6 54 24 73 66 89 45 00 8b 44 24 74 23 44 24 68 8b 6c 24 78 d3 e0 b9 08 00 00 00 2b 4c 24 64 d3 fa 03 c2 69 c0 00 06 00 00 83 7c 24 60 06 8d 84 28 6c 0e 00 00 89 44 24 14 0f8e} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; mov cl, byte ptr [esp + 0x64]; sar eax, 5; mov esi, 1; lea eax, [eax + edx]; movzx edx, byte ptr [esp + 0x73]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x74]; and eax, dword ptr [esp + 0x68]; mov ebp, dword ptr [esp + 0x78]; shl eax, cl; mov ecx, 8; sub ecx, dword ptr [esp + 0x64]; sar edx, cl; add eax, edx; imul eax, eax, 0x600; cmp dword ptr [esp + 0x60], 6; lea eax, [eax + ebp + 0xe6c]; mov dword ptr [esp + 0x14], eax; jle 0x41b3bb;  
		$rule24 = {8b 54 24 74 8b c6 8b 8c 24 a0 00 00 00 88 44 24 73 88 04 11 42 83 7c 24 60 03 89 54 24 74 7f} 
		// mov edx, dword ptr [esp + 0x74]; mov eax, esi; mov ecx, dword ptr [esp + 0xa0]; mov byte ptr [esp + 0x73], al; mov byte ptr [ecx + edx], al; inc edx; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0x74], edx; jg 0x41b459;  
		$rule25 = {29 44 24 48 2b f8 8b c2 66 c1 e8 05 66 2b d0 8d 45 01 66 89 16 8b 6c 24 24 4d 89 6c 24 24 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; lea eax, [ebp + 1]; mov word ptr [esi], dx; mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41b975;  
		$rule26 = {89 44 24 48 b8 00 08 00 00 2b c6 8b f2 c1 f8 05 83 7c 24 3c 00 8d 04 08 66 89 85 00 02 00 00 74} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; cmp dword ptr [esp + 0x3c], 0; lea eax, [eax + ecx]; mov word ptr [ebp + 0x200], ax; je 0x41b3a5;  
		$rule27 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 0b f8 8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 3b f8 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41b414;  
		$rule28 = {29 44 24 48 2b f8 8b c2 66 c1 e8 05 66 2b d0 8b 44 24 18 66 89 55 00 8b 54 24 1c 40 09 14 24 8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov eax, dword ptr [esp + 0x18]; mov word ptr [ebp], dx; mov edx, dword ptr [esp + 0x1c]; inc eax; or dword ptr [esp], edx; mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41ba92;  
		$rule29 = {29 44 24 48 2b f8 8b c1 8d 72 01 66 c1 e8 05 66 2b c8 83 7c 24 3c 00 66 89 8d 00 02 00 00 74} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; cmp dword ptr [esp + 0x3c], 0; mov word ptr [ebp + 0x200], cx; je 0x41b3b3;  
		$rule30 = {89 44 24 48 b8 00 08 00 00 2b c6 c1 f8 05 8d 04 10 66 89 45 00 8b 44 24 18 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; sar eax, 5; lea eax, [eax + edx]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x18]; jmp 0x41bb0f;  
		$rule31 = {8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41ba92;  
		$rule32 = {2b 7c 24 48 83 ce 01 4a 75} 
		// sub edi, dword ptr [esp + 0x48]; or esi, 1; dec edx; jne 0x41ba32;  
		$rule33 = {29 44 24 48 2b f8 8b c2 66 c1 e8 05 66 2b d0 66 89 16 8d 55 01 8b 74 24 28 4e 89 74 24 28 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [esi], dx; lea edx, [ebp + 1]; mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41b8ae;  
		$rule34 = {8b 4c 24 48 2b f8 8b 74 24 60 2b c8 8b c2 66 c1 e8 05 66 2b d0 81 f9 ff ff ff 00 66 89 55 00 8b 6c 24 78 8d 74 75 00 89 74 24 38 77} 
		// mov ecx, dword ptr [esp + 0x48]; sub edi, eax; mov esi, dword ptr [esp + 0x60]; sub ecx, eax; mov eax, edx; shr ax, 5; sub dx, ax; cmp ecx, 0xffffff; mov word ptr [ebp], dx; mov ebp, dword ptr [esp + 0x78]; lea esi, [ebp + esi*2]; mov dword ptr [esp + 0x38], esi; ja 0x41b4b7;  
		$rule35 = {8a 4c 24 30 b8 01 00 00 00 d3 e0 2b d0 03 54 24 2c 83 7c 24 60 03 89 54 24 0c 0f8f} 
		// mov cl, byte ptr [esp + 0x30]; mov eax, 1; shl eax, cl; sub edx, eax; add edx, dword ptr [esp + 0x2c]; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0xc], edx; jg 0x41bb2c;  
		$rule36 = {8b 4c 24 0c 8b 6c 24 74 83 c1 02 39 6c 24 5c 77} 
		// mov ecx, dword ptr [esp + 0xc]; mov ebp, dword ptr [esp + 0x74]; add ecx, 2; cmp dword ptr [esp + 0x5c], ebp; ja 0x41bb9d;  
		$rule37 = {8b 84 24 a0 00 00 00 8b d5 2b 44 24 5c 03 94 24 a0 00 00 00 8d 74 05 00 8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov eax, dword ptr [esp + 0xa0]; mov edx, ebp; sub eax, dword ptr [esp + 0x5c]; add edx, dword ptr [esp + 0xa0]; lea esi, [ebp + eax]; mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41bb75;  
		$rule38 = {8b 4c 24 30 ba 01 00 00 00 89 4c 24 28 8d 2c 12 8b 74 24 10 03 f5 81 7c 24 48 ff ff ff 00 77} 
		// mov ecx, dword ptr [esp + 0x30]; mov edx, 1; mov dword ptr [esp + 0x28], ecx; lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b8d9;  
		$rule39 = {66 8b 11 8b c6 c1 e8 0b 0f b7 ea 0f af c5 3b f8 73} 
		// mov dx, word ptr [ecx]; mov eax, esi; shr eax, 0xb; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41b7f6;  
		$rule40 = {8b 6c 24 38 8b c1 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 3b f8 73} 
		// mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41b523;  
		$rule41 = {89 44 24 48 b8 00 08 00 00 2b c5 c1 64 24 44 04 c1 f8 05 c7 44 24 2c 00 00 00 00 8d 04 10 66 89 01 8b 44 24 44 8d 4c 08 04 89 4c 24 10 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ebp; shl dword ptr [esp + 0x44], 4; sar eax, 5; mov dword ptr [esp + 0x2c], 0; lea eax, [eax + edx]; mov word ptr [ecx], ax; mov eax, dword ptr [esp + 0x44]; lea ecx, [eax + ecx + 4]; mov dword ptr [esp + 0x10], ecx; jmp 0x41b868;  
		$rule42 = {8b 44 24 74 2b 44 24 5c 8b 94 24 a0 00 00 00 0f b6 04 10 89 44 24 40 d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 02 77} 
		// mov eax, dword ptr [esp + 0x74]; sub eax, dword ptr [esp + 0x5c]; mov edx, dword ptr [esp + 0xa0]; movzx eax, byte ptr [eax + edx]; mov dword ptr [esp + 0x40], eax; shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [edx + eax]; ja 0x41b34a;  
		$rule43 = {8b f0 b8 00 08 00 00 2b c5 8b 6c 24 58 c1 f8 05 8b 4c 24 54 8d 04 10 8b 54 24 38 89 4c 24 50 8b 4c 24 78 66 89 82 80 01 00 00 8b 44 24 5c 89 6c 24 54 89 44 24 58 33 c0 83 7c 24 60 06 0f 9f c0 81 c1 64 06 00 00 8d 04 40 89 44 24 60 e9} 
		// mov esi, eax; mov eax, 0x800; sub eax, ebp; mov ebp, dword ptr [esp + 0x58]; sar eax, 5; mov ecx, dword ptr [esp + 0x54]; lea eax, [eax + edx]; mov edx, dword ptr [esp + 0x38]; mov dword ptr [esp + 0x50], ecx; mov ecx, dword ptr [esp + 0x78]; mov word ptr [edx + 0x180], ax; mov eax, dword ptr [esp + 0x5c]; mov dword ptr [esp + 0x54], ebp; mov dword ptr [esp + 0x58], eax; xor eax, eax; cmp dword ptr [esp + 0x60], 6; setg al; add ecx, 0x664; lea eax, [eax + eax*2]; mov dword ptr [esp + 0x60], eax; jmp 0x41b797;  
		$rule44 = {83 44 24 60 07 83 fa 03 8b c2 7e} 
		// add dword ptr [esp + 0x60], 7; cmp edx, 3; mov eax, edx; jle 0x41b956;  
		$rule45 = {8d 50 c0 83 fa 03 89 14 24 0f8e} 
		// lea edx, [eax - 0x40]; cmp edx, 3; mov dword ptr [esp], edx; jle 0x41bb22;  
		$rule46 = {8b 34 24 46 89 74 24 5c 74} 
		// mov esi, dword ptr [esp]; inc esi; mov dword ptr [esp + 0x5c], esi; je 0x41bb86;  
		$rule47 = {8b c2 8b f2 d1 f8 83 e6 01 8d 48 ff 83 ce 02 83 fa 0d 89 4c 24 20 7f} 
		// mov eax, edx; mov esi, edx; sar eax, 1; and esi, 1; lea ecx, [eax - 1]; or esi, 2; cmp edx, 0xd; mov dword ptr [esp + 0x20], ecx; jg 0x41ba2f;  
		$rule48 = {8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 30 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 03 f5 81 7c 24 48 ff ff ff 00 77} 
		// mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [eax + esi + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b9a0;  
		$rule49 = {8d 50 fb 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [eax - 5]; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41ba54;  
		$rule50 = {8b 44 24 78 c1 e6 04 89 34 24 05 44 06 00 00 c7 44 24 20 04 00 00 00 89 44 24 04 c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 03 c0 89 44 24 18 03 e8 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, dword ptr [esp + 0x78]; shl esi, 4; mov dword ptr [esp], esi; add eax, 0x644; mov dword ptr [esp + 0x20], 4; mov dword ptr [esp + 4], eax; mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41bac0;  
		$rule51 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 0b f8 8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 3b f8 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41b9cc;  
		$rule52 = {8b f1 2b f8 2b f0 8b c2 66 c1 e8 05 8b 4c 24 38 66 2b d0 81 fe ff ff ff 00 66 89 91 80 01 00 00 77} 
		// mov esi, ecx; sub edi, eax; sub esi, eax; mov eax, edx; shr ax, 5; mov ecx, dword ptr [esp + 0x38]; sub dx, ax; cmp esi, 0xffffff; mov word ptr [ecx + 0x180], dx; ja 0x41b55b;  
		$rule53 = {8b 6c 24 38 8b d6 c1 ea 0b 66 8b 8d 98 01 00 00 0f b7 c1 0f af d0 3b fa 0f83} 
		// mov ebp, dword ptr [esp + 0x38]; mov edx, esi; shr edx, 0xb; mov cx, word ptr [ebp + 0x198]; movzx eax, cx; imul edx, eax; cmp edi, edx; jae 0x41b65c;  
		$rule54 = {bd 00 08 00 00 8b f2 2b e8 c7 44 24 34 00 08 00 00 8b c5 c1 f8 05 8d 04 08 8b 4c 24 38 66 89 81 98 01 00 00 8b 44 24 60 8b 4c 24 44 c1 e0 05 03 44 24 78 81 fa ff ff ff 00 8d 2c 48 77} 
		// mov ebp, 0x800; mov esi, edx; sub ebp, eax; mov dword ptr [esp + 0x34], 0x800; mov eax, ebp; sar eax, 5; lea eax, [eax + ecx]; mov ecx, dword ptr [esp + 0x38]; mov word ptr [ecx + 0x198], ax; mov eax, dword ptr [esp + 0x60]; mov ecx, dword ptr [esp + 0x44]; shl eax, 5; add eax, dword ptr [esp + 0x78]; cmp edx, 0xffffff; lea ebp, [eax + ecx*2]; ja 0x41b5cd;  
		$rule55 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 0b f8 8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 ca 0f af c1 3b f8 0f83} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41b474;  
		$rule56 = {66 8b 95 e0 01 00 00 8b c6 c1 e8 0b 0f b7 ca 0f af c1 3b f8 73} 
		// mov dx, word ptr [ebp + 0x1e0]; mov eax, esi; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41b643;  
		$rule57 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 0b f8 8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 f2 0f af c6 3b f8 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx esi, dx; imul eax, esi; cmp edi, eax; jae 0x41baf0;  
		$rule58 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 0b f8 d1 6c 24 48 03 f6 3b 7c 24 48 72} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41ba67;  
		$rule59 = {2b f0 2b f8 8b c2 66 c1 e8 05 66 2b d0 66 89 95 e0 01 00 00 e9} 
		// sub esi, eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [ebp + 0x1e0], dx; jmp 0x41b77b;  
		$rule60 = {33 c0 83 7c 24 60 06 8b 4c 24 78 0f 9f c0 81 c1 68 0a 00 00 8d 44 40 08 89 44 24 60 81 fe ff ff ff 00 77} 
		// xor eax, eax; cmp dword ptr [esp + 0x60], 6; mov ecx, dword ptr [esp + 0x78]; setg al; add ecx, 0xa68; lea eax, [eax + eax*2 + 8]; mov dword ptr [esp + 0x60], eax; cmp esi, 0xffffff; ja 0x41b7b5;  
		$rule61 = {8b 6c 24 78 d3 e6 03 d2 89 34 24 8d 44 75 00 2b c2 05 5e 05 00 00 89 44 24 04 eb} 
		// mov ebp, dword ptr [esp + 0x78]; shl esi, cl; add edx, edx; mov dword ptr [esp], esi; lea eax, [ebp + esi*2]; sub eax, edx; add eax, 0x55e; mov dword ptr [esp + 4], eax; jmp 0x41ba85;  
		$rule62 = {c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 03 c0 89 44 24 18 03 e8 81 7c 24 48 ff ff ff 00 77} 
		// mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41bac0;  
		$rule63 = {66 c7 00 00 04 83 c0 02 } 
		// mov word ptr [eax], 0x400; add eax, 2; loop 0x41b1ec;  
		$rule64 = {b8 03 00 00 00 8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 30 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 03 f5 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, 3; mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [eax + esi + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41b9a0;  
		
	condition:
		pe.is_32bit() and (45 of them) and (pe.overlay.offset == 0 or for 31 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_mpress_v127
{
	meta:
		packer="mpress"
		generator="PackGenome"
		versions="v127"
	strings:
		$rule0 = {8b d9 ac 41 24 fe 3c e8 75} 
		// mov ebx, ecx; lodsb al, byte ptr [esi]; inc ecx; and al, 0xfe; cmp al, 0xe8; jne 0x41b0b5;  
		$rule1 = {8b 5d f8 8a 08 ff 45 f8 40 ff 4d ec 88 0c 1f 75} 
		// mov ebx, dword ptr [ebp - 8]; mov cl, byte ptr [eax]; inc dword ptr [ebp - 8]; inc eax; dec dword ptr [ebp - 0x14]; mov byte ptr [edi + ebx], cl; jne 0x41b25e;  
		$rule2 = {49 8a 44 39 06 74} 
		// dec ecx; mov al, byte ptr [ecx + edi + 6]; je 0x41b0a2;  
		$rule3 = {0f b6 45 ff 8b 7d 08 2b f8 3b f7 0f83} 
		// movzx eax, byte ptr [ebp - 1]; mov edi, dword ptr [ebp + 8]; sub edi, eax; cmp esi, edi; jae 0x41b2f5;  
		$rule4 = {80 7d ff 00 0f b6 1c 32 74} 
		// cmp byte ptr [ebp - 1], 0; movzx ebx, byte ptr [edx + esi]; je 0x41b28b;  
		$rule5 = {80 7d ff 00 8b 1c 32 74} 
		// cmp byte ptr [ebp - 1], 0; mov ebx, dword ptr [edx + esi]; je 0x41b169;  
		$rule6 = {8b 45 f8 2b c7 85 db 74} 
		// mov eax, dword ptr [ebp - 8]; sub eax, edi; test ebx, ebx; je 0x41b298;  
		$rule7 = {8b 7d f0 03 c7 89 5d ec 8b 5d f8 8a 08 ff 45 f8 40 ff 4d ec 88 0c 1f 75} 
		// mov edi, dword ptr [ebp - 0x10]; add eax, edi; mov dword ptr [ebp - 0x14], ebx; mov ebx, dword ptr [ebp - 8]; mov cl, byte ptr [eax]; inc dword ptr [ebp - 8]; inc eax; dec dword ptr [ebp - 0x14]; mov byte ptr [edi + ebx], cl; jne 0x41b25e;  
		$rule8 = {ff 45 f4 d0 e1 83 7d f4 08 88 4d fe 0f8c} 
		// inc dword ptr [ebp - 0xc]; shl cl, 1; cmp dword ptr [ebp - 0xc], 8; mov byte ptr [ebp - 2], cl; jl 0x41b144;  
		$rule9 = {83 e3 03 c1 ef 02 83 eb 00 74} 
		// and ebx, 3; shr edi, 2; sub ebx, 0; je 0x41b1dd;  
		$rule10 = {8b 7d f8 8b 45 f0 ff 45 f8 88 1c 38 46 ff 45 f4 d0 e1 83 7d f4 08 88 4d fe 0f8c} 
		// mov edi, dword ptr [ebp - 8]; mov eax, dword ptr [ebp - 0x10]; inc dword ptr [ebp - 8]; mov byte ptr [eax + edi], bl; inc esi; inc dword ptr [ebp - 0xc]; shl cl, 1; cmp dword ptr [ebp - 0xc], 8; mov byte ptr [ebp - 2], cl; jl 0x41b144;  
		$rule11 = {0f b6 44 32 01 c1 eb 04 c1 e0 04 0b d8 8b 7d f8 8b 45 f0 ff 45 f8 88 1c 38 46 ff 45 f4 d0 e1 83 7d f4 08 88 4d fe 0f8c} 
		// movzx eax, byte ptr [edx + esi + 1]; shr ebx, 4; shl eax, 4; or ebx, eax; mov edi, dword ptr [ebp - 8]; mov eax, dword ptr [ebp - 0x10]; inc dword ptr [ebp - 8]; mov byte ptr [eax + edi], bl; inc esi; inc dword ptr [ebp - 0xc]; shl cl, 1; cmp dword ptr [ebp - 0xc], 8; mov byte ptr [ebp - 2], cl; jl 0x41b144;  
		$rule12 = {0f b7 1c 32 c1 eb 04 eb} 
		// movzx ebx, word ptr [edx + esi]; shr ebx, 4; jmp 0x41b1fc;  
		$rule13 = {81 e7 ff 3f 00 00 81 c7 41 04 00 00 46 eb} 
		// and edi, 0x3fff; add edi, 0x441; inc esi; jmp 0x41b1e1;  
		$rule14 = {0f b6 45 ff 8b 4d 08 2b c8 3b f1 0f82} 
		// movzx eax, byte ptr [ebp - 1]; mov ecx, dword ptr [ebp + 8]; sub ecx, eax; cmp esi, ecx; jb 0x41b127;  
		$rule15 = {80 7d ff 00 8a 0c 32 74} 
		// cmp byte ptr [ebp - 1], 0; mov cl, byte ptr [edx + esi]; je 0x41b13c;  
		$rule16 = {81 e7 ff 03 00 00 03 f0 83 c7 41 eb} 
		// and edi, 0x3ff; add esi, eax; add edi, 0x41; jmp 0x41b190;  
		$rule17 = {83 e7 3f 47 80 7d ff 00 74} 
		// and edi, 0x3f; inc edi; cmp byte ptr [ebp - 1], 0; je 0x41b1f0;  
		$rule18 = {46 83 65 f4 00 88 4d fe 0f b6 45 ff 8b 7d 08 2b f8 3b f7 0f83} 
		// inc esi; and dword ptr [ebp - 0xc], 0; mov byte ptr [ebp - 2], cl; movzx eax, byte ptr [ebp - 1]; mov edi, dword ptr [ebp + 8]; sub edi, eax; cmp esi, edi; jae 0x41b2f5;  
		$rule19 = {8a 44 32 01 c0 e9 04 c0 e0 04 0a c8 46 83 65 f4 00 88 4d fe 0f b6 45 ff 8b 7d 08 2b f8 3b f7 0f83} 
		// mov al, byte ptr [edx + esi + 1]; shr cl, 4; shl al, 4; or cl, al; inc esi; and dword ptr [ebp - 0xc], 0; mov byte ptr [ebp - 2], cl; movzx eax, byte ptr [ebp - 1]; mov edi, dword ptr [ebp + 8]; sub edi, eax; cmp esi, edi; jae 0x41b2f5;  
		$rule20 = {43 83 c1 04 ad 0b c0 78} 
		// inc ebx; add ecx, 4; lodsd eax, dword ptr [esi]; or eax, eax; js 0x41b0d2;  
		$rule21 = {2b c3 89 46 fc eb} 
		// sub eax, ebx; mov dword ptr [esi - 4], eax; jmp 0x41b0b5;  
		$rule22 = {81 e7 ff ff 03 00 8d 74 30 01 81 c7 41 44 00 00 eb} 
		// and edi, 0x3ffff; lea esi, [eax + esi + 1]; add edi, 0x4441; jmp 0x41b190;  
		$rule23 = {8b 0c 32 8b 5d f8 8b 7d f0 83 45 f8 04 83 c6 04 48 89 0c 1f 75} 
		// mov ecx, dword ptr [edx + esi]; mov ebx, dword ptr [ebp - 8]; mov edi, dword ptr [ebp - 0x10]; add dword ptr [ebp - 8], 4; add esi, 4; dec eax; mov dword ptr [edi + ebx], ecx; jne 0x41b2df;  
		
	condition:
		pe.is_32bit() and (16 of them) and (pe.overlay.offset == 0 or for 11 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// WinLicense
rule packer_WinLicense_v239_compress_secureEngine_combined
{
	meta:
		packer="WinLicense"
		generator="PackGenome"
		version="v239"
		configs="compress_secureEngine compress_all_api1 compress_all compress_all_delphiBCB compress_all_api2 compress_all_resourcesEnc"
	strings:
		$rule0 = {31 06 01 1e 83 c6 04 49 eb} 
		// xor dword ptr [esi], eax; add dword ptr [esi], ebx; add esi, 4; dec ecx; jmp 0x85605a;  
		$rule1 = {58 89 c3 40 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3b cc 75} 
		// pop eax; mov ebx, eax; inc eax; sub eax, 0x19c000; sub eax, 0x6c70dd4; add eax, 0x6c70dcb; cmp byte ptr [ebx], 0xcc;  
		$rule2 = {c6 03 00 bb 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 e8} 
		// mov byte ptr [ebx], 0; mov ebx, 0x1000; push 0x10634a31; push 0x107a841e; push ebx; push eax;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_WinLicense_v239_compress_application_combined
{
	meta:
		packer="WinLicense"
		generator="PackGenome"
		version="v239"
		config="compress_application"
	strings:
		$rule0 = {50 30 04 0a 00 64 0a 01 c1 e8 10 30 44 0a 02 00 64 0a 03 58 83 e9 04 75} 
		// push eax; xor byte ptr [edx + ecx], al; add byte ptr [edx + ecx + 1], ah; shr eax, 0x10; xor byte ptr [edx + ecx + 2], al; add byte ptr [edx + ecx + 3], ah; pop eax; sub ecx, 4; jne 0x5e7c3b;  
		$rule1 = {fe 0f 47 49 75} 
		// dec byte ptr [edi]; inc edi; dec ecx; jne 0x41e958;  
		$rule2 = {89 0c 24 e9} 
		// mov dword ptr [esp], ecx; jmp 0x5d343c;  
		$rule3 = {53 e9} 
		// push ebx; jmp 0x5b5c55;  
		$rule4 = {81 ec 04 00 00 00 e9} 
		// sub esp, 4; jmp 0x5b5a5b;  
		$rule5 = {83 c4 04 e9} 
		// add esp, 4; jmp 0x59e972;  
		$rule6 = {55 e9} 
		// push ebp; jmp 0x59e81b;  
		$rule7 = {5b e9} 
		// pop ebx; jmp 0x59eb02;  
		$rule8 = {89 04 24 e9} 
		// mov dword ptr [esp], eax; jmp 0x59e106;  
		$rule9 = {57 e9} 
		// push edi; jmp 0x5ddc9e;  
		$rule10 = {54 e9} 
		// push esp; jmp 0x5de3bd;  
		$rule11 = {8b 24 24 e9} 
		// mov esp, dword ptr [esp]; jmp 0x5de4e7;  
		$rule12 = {5a e9} 
		// pop edx; jmp 0x5de26a;  
		$rule13 = {58 e9} 
		// pop eax; jmp 0x5de764;  
		$rule14 = {5f e9} 
		// pop edi; jmp 0x5ddeae;  
		$rule15 = {5e e9} 
		// pop esi; jmp 0x5de36f;  
		$rule16 = {ff 34 24 e9} 
		// push dword ptr [esp]; jmp 0x5de89e;  
		$rule17 = {52 e9} 
		// push edx; jmp 0x5de069;  
		$rule18 = {89 3c 24 e9} 
		// mov dword ptr [esp], edi; jmp 0x5c3fe2;  
		$rule19 = {5c e9} 
		// pop esp; jmp 0x616c1b;  
		
	condition:
		pe.is_32bit() and (14 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_WinLicense_v239_compress_resources_combined
{
	meta:
		packer="WinLicense"
		generator="PackGenome"
		version="v239"
		config="compress_resources"
	strings:
		$rule0 = {50 30 04 0a 00 64 0a 01 c1 e8 10 30 44 0a 02 00 64 0a 03 58 83 e9 04 75} 
		// push eax; xor byte ptr [edx + ecx], al; add byte ptr [edx + ecx + 1], ah; shr eax, 0x10; xor byte ptr [edx + ecx + 2], al; add byte ptr [edx + ecx + 3], ah; pop eax; sub ecx, 4; jne 0x5e199a;  
		$rule1 = {fe 0f 47 49 75} 
		// dec byte ptr [edi]; inc edi; dec ecx; jne 0x41e96c;  
		$rule2 = {52 e9} 
		// push edx; jmp 0x61c4c7;  
		$rule3 = {59 e9} 
		// pop ecx; jmp 0x61c743;  
		$rule4 = {51 e9} 
		// push ecx; jmp 0x61c4ef;  
		$rule5 = {53 e9} 
		// push ebx; jmp 0x61cb57;  
		$rule6 = {5a e9} 
		// pop edx; jmp 0x61cc78;  
		$rule7 = {89 2c 24 e9} 
		// mov dword ptr [esp], ebp; jmp 0x5d283f;  
		$rule8 = {81 c4 04 00 00 00 e9} 
		// add esp, 4; jmp 0x5d2cf7;  
		$rule9 = {50 e9} 
		// push eax; jmp 0x5d2e02;  
		$rule10 = {57 e9} 
		// push edi; jmp 0x5b86e1;  
		$rule11 = {83 c4 04 e9} 
		// add esp, 4; jmp 0x6968a4;  
		$rule12 = {87 0c 24 e9} 
		// xchg dword ptr [esp], ecx; jmp 0x5f0635;  
		$rule13 = {55 e9} 
		// push ebp; jmp 0x5f07aa;  
		$rule14 = {58 e9} 
		// pop eax; jmp 0x5f0ca1;  
		$rule15 = {89 1c 24 e9} 
		// mov dword ptr [esp], ebx; jmp 0x5c743e;  
		$rule16 = {83 ec 04 e9} 
		// sub esp, 4; jmp 0x5a4471;  
		$rule17 = {5c e9} 
		// pop esp; jmp 0x5a4aa9;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_WinLicense_v239_compress_all_full_combined
{
	meta:
		packer="WinLicense"
		generator="PackGenome"
		version="v239"
		config="compress_all_full"
	strings:
		$rule0 = {31 06 01 1e 83 c6 04 49 eb} 
		// xor dword ptr [esi], eax; add dword ptr [esi], ebx; add esi, 4; dec ecx; jmp 0x88105a;  
		$rule1 = {58 89 c3 40 2d 00 e0 1a 00 2d ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3b cc 75} 
		// pop eax; mov ebx, eax; inc eax; sub eax, 0x1ae000; sub eax, 0x6b20dd4; add eax, 0x6b20dcb; cmp byte ptr [ebx], 0xcc;  
		$rule2 = {c6 03 00 bb 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 e8} 
		// mov byte ptr [ebx], 0; mov ebx, 0x1000; push 0x6bc6a292; push 0x322ff974; push ebx; push eax;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Fsg
rule packer_Fsg
{
	meta:
		packer="Fsg"
		generator="PackGenome"
		versions="v13"
	strings:
		$rule0 = {41 41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x427f7c;  
		$rule1 = {95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x427f7c;  
		$rule2 = {a4 b6 80 ff} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov dh, 0x80; call dword ptr [ebx];  
		$rule3 = {41 95 8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; xchg eax, ebp; mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x427f7c;  
		$rule4 = {8b c5 b6 00 56 8b f7 2b f0 f3 a4 5e eb} 
		// mov eax, ebp; mov dh, 0; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x427f7c;  
		$rule5 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x427f7c;  
		$rule6 = {b6 80 41 b0 10 ff} 
		// mov dh, 0x80; inc ecx; mov al, 0x10; call dword ptr [ebx];  
		$rule7 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x427fdf;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 5 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// ACProtect
rule packer_ACProtect_v132_compress2_combined
{
	meta:
		packer="ACProtect"
		generator="PackGenome"
		version="v132"
		configs="compress2 compress1_codereplace compress1_import compress1_full_DYNAMIC_EMBEDDED compress1_integritycheck compress1"
	strings:
		$rule0 = {13 c0 49 75} 
		// adc eax, eax; dec ecx; jne 0x437f79;  
		$rule1 = {90 90 90 90 8b 4c 24 10 33 c0 03 d2 75} 
		// nop ; nop ; nop ; nop ; mov ecx, dword ptr [esp + 0x10]; xor eax, eax; add edx, edx; jne 0x437f89;  
		$rule2 = {02 44 24 0c 88 07 47 eb} 
		// add al, byte ptr [esp + 0xc]; mov byte ptr [edi], al; inc edi; jmp 0x437f5d;  
		$rule3 = {49 49 75} 
		// dec ecx; dec ecx; jne 0x43816d;  
		$rule4 = {8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x437f5d;  
		$rule5 = {49 8b c1 8b 4c 24 14 8b e8 33 c0 d3 e5 33 c0 03 d2 75} 
		// dec ecx; mov eax, ecx; mov ecx, dword ptr [esp + 0x14]; mov ebp, eax; xor eax, eax; shl ebp, cl; xor eax, eax; add edx, edx; jne 0x43818c;  
		$rule6 = {41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x437f5d;  
		$rule7 = {90 90 90 90 8b 16 83 c6 04 f9 13 d2 13 c0 49 75} 
		// nop ; nop ; nop ; nop ; mov edx, dword ptr [esi]; add esi, 4; stc ; adc edx, edx; adc eax, eax; dec ecx; jne 0x437f79;  
		$rule8 = {8b c8 8b c5 83 c1 02 85 c0 74} 
		// mov ecx, eax; mov eax, ebp; add ecx, 2; test eax, eax; je 0x4380e2;  
		$rule9 = {90 90 90 90 8b d8 e9} 
		// nop ; nop ; nop ; nop ; mov ebx, eax; jmp 0x4381ec;  
		$rule10 = {13 c9 03 d2 75} 
		// adc ecx, ecx; add edx, edx; jne 0x438166;  
		$rule11 = {90 90 90 90 8b c3 b9 01 00 00 00 03 d2 75} 
		// nop ; nop ; nop ; nop ; mov eax, ebx; mov ecx, 1; add edx, edx; jne 0x438154;  
		$rule12 = {90 90 90 90 8b 16 83 c6 04 f9 13 d2 73} 
		// nop ; nop ; nop ; nop ; mov edx, dword ptr [esi]; add esi, 4; stc ; adc edx, edx; jae 0x437f97;  
		$rule13 = {41 41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// inc ecx; inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x437f5d;  
		$rule14 = {90 90 90 90 41 41 41 41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// nop ; nop ; nop ; nop ; inc ecx; inc ecx; inc ecx; inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x437f5d;  
		
	condition:
		pe.is_32bit() and (10 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_ACProtect_v132_no_compress_combined
{
	meta:
		packer="ACProtect"
		generator="PackGenome"
		version="v132"
		config="no_compress"
	strings:
		$rule0 = {8a 01 41 84 c0 75} 
		// mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x4047c6;  
		$rule1 = {89 75 d4 3b f3 74} 
		// mov dword ptr [ebp - 0x2c], esi; cmp esi, ebx; je 0x4061f5;  
		$rule2 = {8b 06 89 45 e0 ff 37 50 e8} 
		// mov eax, dword ptr [esi]; mov dword ptr [ebp - 0x20], eax; push dword ptr [edi]; push eax; call 0x40626c;  
		$rule3 = {59 59 84 c0 74} 
		// pop ecx; pop ecx; test al, al; je 0x4061f0;  
		$rule4 = {8b ff 55 8b ec 8b 45 08 85 c0 74} 
		// mov edi, edi; push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 8]; test eax, eax; je 0x406297;  
		$rule5 = {40 80 3c 08 00 75} 
		// inc eax; cmp byte ptr [eax + ecx], 0; jne 0x40f36d;  
		$rule6 = {32 c0 5d c3} 
		// xor al, al; pop ebp; ret ;  
		$rule7 = {88 84 05 fc fe ff ff 40 3b c7 72} 
		// mov byte ptr [ebp + eax - 0x104], al; inc eax; cmp eax, edi; jb 0x408a4d;  
		$rule8 = {0f b7 8c 45 fc f8 ff ff f6 c1 01 74} 
		// movzx ecx, word ptr [ebp + eax*2 - 0x704]; test cl, 1; je 0x408b15;  
		$rule9 = {8a cb 88 8c 06 19 01 00 00 40 3b c7 72} 
		// mov cl, bl; mov byte ptr [esi + eax + 0x119], cl; inc eax; cmp eax, edi; jb 0x408afa;  
		$rule10 = {5f 5b 5d c3} 
		// pop edi; pop ebx; pop ebp; ret ;  
		$rule11 = {c6 84 05 fc fe ff ff 20 40 3b c2 76} 
		// mov byte ptr [ebp + eax - 0x104], 0x20; inc eax; cmp eax, edx; jbe 0x408a77;  
		$rule12 = {8b ff 55 8b ec 83 7d 08 00 74} 
		// mov edi, edi; push ebp; mov ebp, esp; cmp dword ptr [ebp + 8], 0; je 0x405b93;  
		$rule13 = {8b ff 55 8b ec 56 8b 75 08 85 f6 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push esi; mov esi, dword ptr [ebp + 8]; test esi, esi; je 0x405b17;  
		$rule14 = {6a e0 33 d2 58 f7 f6 3b 45 0c 72} 
		// push -0x20; xor edx, edx; pop eax; div esi; cmp eax, dword ptr [ebp + 0xc]; jb 0x405b4b;  
		$rule15 = {0f af 75 0c 85 f6 75} 
		// imul esi, dword ptr [ebp + 0xc]; test esi, esi; jne 0x405b36;  
		$rule16 = {42 8b ce 8d 79 01 8a 01 41 84 c0 75} 
		// inc edx; mov ecx, esi; lea edi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x4047c6;  
		$rule17 = {2b cf 46 03 f1 8a 06 84 c0 75} 
		// sub ecx, edi; inc esi; add esi, ecx; mov al, byte ptr [esi]; test al, al; jne 0x4047bc;  
		$rule18 = {8b cb 8d 71 01 8a 01 41 84 c0 75} 
		// mov ecx, ebx; lea esi, [ecx + 1]; mov al, byte ptr [ecx]; inc ecx; test al, al; jne 0x4047f5;  
		$rule19 = {2b ce 8d 41 01 89 45 f8 80 fa 3d 74} 
		// sub ecx, esi; lea eax, [ecx + 1]; mov dword ptr [ebp - 8], eax; cmp dl, 0x3d; je 0x404840;  
		$rule20 = {6a 01 50 e8} 
		// push 1; push eax; call 0x405afe;  
		$rule21 = {83 c4 0c 85 c0 75} 
		// add esp, 0xc; test eax, eax; jne 0x40486a;  
		$rule22 = {8b 45 fc 6a 00 89 30 83 c0 04 89 45 fc e8} 
		// mov eax, dword ptr [ebp - 4]; push 0; mov dword ptr [eax], esi; add eax, 4; mov dword ptr [ebp - 4], eax; call 0x405b5b;  
		$rule23 = {8b 45 f8 59 03 d8 8a 13 84 d2 75} 
		// mov eax, dword ptr [ebp - 8]; pop ecx; add ebx, eax; mov dl, byte ptr [ebx]; test dl, dl; jne 0x4047f0;  
		$rule24 = {8b ff 55 8b ec 53 57 8b f9 8b 4d 08 c6 47 0c 00 8d 5f 04 85 c9 74} 
		// mov edi, edi; push ebp; mov ebp, esp; push ebx; push edi; mov edi, ecx; mov ecx, dword ptr [ebp + 8]; mov byte ptr [edi + 0xc], 0; lea ebx, [edi + 4]; test ecx, ecx; je 0x4030a8;  
		$rule25 = {8b c7 5f 5b 5d } 
		// mov eax, edi; pop edi; pop ebx; pop ebp; ret 4;  
		$rule26 = {8b 46 10 8a 00 88 46 31 84 c0 0f85} 
		// mov eax, dword ptr [esi + 0x10]; mov al, byte ptr [eax]; mov byte ptr [esi + 0x31], al; test al, al; jne 0x4033ea;  
		$rule27 = {8b ff 55 8b ec 56 68 d4 37 41 00 68 cc 37 41 00 68 20 2c 41 00 6a 12 e8} 
		// mov edi, edi; push ebp; mov ebp, esp; push esi; push 0x4137d4; push 0x4137cc; push 0x412c20; push 0x12; call 0x405cc4;  
		$rule28 = {83 4f f8 ff 80 67 0d f8 89 1f 8d 7f 38 89 5f cc 8d 47 e0 c7 47 d0 00 00 0a 0a c6 47 d4 0a 89 5f d6 88 5f da 3b c6 75} 
		// or dword ptr [edi - 8], 0xffffffff; and byte ptr [edi + 0xd], 0xf8; mov dword ptr [edi], ebx; lea edi, [edi + 0x38]; mov dword ptr [edi - 0x34], ebx; lea eax, [edi - 0x20]; mov dword ptr [edi - 0x30], 0xa0a0000; mov byte ptr [edi - 0x2c], 0xa; mov dword ptr [edi - 0x2a], ebx; mov byte ptr [edi - 0x26], bl; cmp eax, esi; jne 0x4096d0;  
		$rule29 = {53 68 a0 0f 00 00 8d 47 e0 50 e8} 
		// push ebx; push 0xfa0; lea eax, [edi - 0x20]; push eax; call 0x405f02;  
		$rule30 = {8b ff 55 8b ec 8a 4d 08 8d 41 e0 3c 5a 77} 
		// mov edi, edi; push ebp; mov ebp, esp; mov cl, byte ptr [ebp + 8]; lea eax, [ecx - 0x20]; cmp al, 0x5a; ja 0x4032b2;  
		$rule31 = {ff 46 10 39 5e 18 0f8c} 
		// inc dword ptr [esi + 0x10]; cmp dword ptr [esi + 0x18], ebx; jl 0x403482;  
		$rule32 = {0f be c1 83 e8 20 83 e0 7f 8b 0c c5 44 2c 41 00 eb} 
		// movsx eax, cl; sub eax, 0x20; and eax, 0x7f; mov ecx, dword ptr [eax*8 + 0x412c44]; jmp 0x4032b4;  
		$rule33 = {ff 03 85 f6 74} 
		// inc dword ptr [ebx]; test esi, esi; je 0x4045a9;  
		$rule34 = {59 85 c0 74} 
		// pop ecx; test eax, eax; je 0x4045c9;  
		$rule35 = {8a 45 fe 84 c0 74} 
		// mov al, byte ptr [ebp - 2]; test al, al; je 0x4045e9;  
		$rule36 = {8b ff 55 8b ec 83 ec 10 56 ff 75 08 8d 4d f0 e8} 
		// mov edi, edi; push ebp; mov ebp, esp; sub esp, 0x10; push esi; push dword ptr [ebp + 8]; lea ecx, [ebp - 0x10]; call 0x403088;  
		$rule37 = {83 c4 04 58 e9} 
		// add esp, 4; pop eax; jmp 0x43086e;  
		$rule38 = {8a 4d ff 84 c9 75} 
		// mov cl, byte ptr [ebp - 1]; test cl, cl; jne 0x40458c;  
		$rule39 = {88 8c 06 19 01 00 00 40 3b c7 72} 
		// mov byte ptr [esi + eax + 0x119], cl; inc eax; cmp eax, edi; jb 0x408afa;  
		$rule40 = {8b ff 55 8b ec 8b 4d 08 83 f9 fe 75} 
		// mov edi, edi; push ebp; mov ebp, esp; mov ecx, dword ptr [ebp + 8]; cmp ecx, -2; jne 0x40d812;  
		$rule41 = {ff 31 0f be 45 08 50 e8} 
		// push dword ptr [ecx]; movsx eax, byte ptr [ebp + 8]; push eax; call 0x407cec;  
		$rule42 = {8b ff 55 8b ec 8b 55 0c 83 6a 08 01 79} 
		// mov edi, edi; push ebp; mov ebp, esp; mov edx, dword ptr [ebp + 0xc]; sub dword ptr [edx + 8], 1; jns 0x407d07;  
		$rule43 = {8b 02 8a 4d 08 88 08 ff 02 0f b6 c1 5d c3} 
		// mov eax, dword ptr [edx]; mov cl, byte ptr [ebp + 8]; mov byte ptr [eax], cl; inc dword ptr [edx]; movzx eax, cl; pop ebp; ret ;  
		$rule44 = {8a 01 41 3c 0a 75} 
		// mov al, byte ptr [ecx]; inc ecx; cmp al, 0xa; jne 0x40b2e4;  
		$rule45 = {88 06 46 8d 45 fb 3b f0 72} 
		// mov byte ptr [esi], al; inc esi; lea eax, [ebp - 5]; cmp esi, eax; jb 0x40b2d2;  
		$rule46 = {8b ff 53 56 57 ff} 
		// mov edi, edi; push ebx; push esi; push edi; call dword ptr [0x41203c];  
		$rule47 = {42 89 30 8d 40 04 3b d1 75} 
		// inc edx; mov dword ptr [eax], esi; lea eax, [eax + 4]; cmp edx, ecx; jne 0x405ff8;  
		$rule48 = {40 89 39 8d 49 04 3b c2 75} 
		// inc eax; mov dword ptr [ecx], edi; lea ecx, [ecx + 4]; cmp eax, edx; jne 0x40506d;  
		
	condition:
		pe.is_32bit() and (34 of them) and (pe.overlay.offset == 0 or for 23 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_ACProtect_v141_compress2_combined
{
	meta:
		packer="ACProtect"
		generator="PackGenome"
		version="v141"
		configs="compress2 compress1_codereplace compress1_import compress1_full_DYNAMIC_EMBEDDED compress1_integritycheck compress1"
	strings:
		$rule0 = {13 c0 49 75} 
		// adc eax, eax; dec ecx; jne 0x432208;  
		$rule1 = {90 90 90 90 8b 4c 24 10 33 c0 03 d2 75} 
		// nop ; nop ; nop ; nop ; mov ecx, dword ptr [esp + 0x10]; xor eax, eax; add edx, edx; jne 0x432218;  
		$rule2 = {02 44 24 0c 88 07 47 eb} 
		// add al, byte ptr [esp + 0xc]; mov byte ptr [edi], al; inc edi; jmp 0x4321ec;  
		$rule3 = {49 49 75} 
		// dec ecx; dec ecx; jne 0x4323fc;  
		$rule4 = {8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x4321ec;  
		$rule5 = {49 8b c1 8b 4c 24 14 8b e8 33 c0 d3 e5 33 c0 03 d2 75} 
		// dec ecx; mov eax, ecx; mov ecx, dword ptr [esp + 0x14]; mov ebp, eax; xor eax, eax; shl ebp, cl; xor eax, eax; add edx, edx; jne 0x43241b;  
		$rule6 = {41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x4321ec;  
		$rule7 = {90 90 90 90 8b 16 83 c6 04 f9 13 d2 13 c0 49 75} 
		// nop ; nop ; nop ; nop ; mov edx, dword ptr [esi]; add esi, 4; stc ; adc edx, edx; adc eax, eax; dec ecx; jne 0x432208;  
		$rule8 = {8b c8 8b c5 83 c1 02 85 c0 74} 
		// mov ecx, eax; mov eax, ebp; add ecx, 2; test eax, eax; je 0x432371;  
		$rule9 = {90 90 90 90 8b d8 e9} 
		// nop ; nop ; nop ; nop ; mov ebx, eax; jmp 0x43247b;  
		$rule10 = {13 c9 03 d2 75} 
		// adc ecx, ecx; add edx, edx; jne 0x4323f5;  
		$rule11 = {90 90 90 90 8b c3 b9 01 00 00 00 03 d2 75} 
		// nop ; nop ; nop ; nop ; mov eax, ebx; mov ecx, 1; add edx, edx; jne 0x4323e3;  
		$rule12 = {90 90 90 90 8b 16 83 c6 04 f9 13 d2 73} 
		// nop ; nop ; nop ; nop ; mov edx, dword ptr [esi]; add esi, 4; stc ; adc edx, edx; jae 0x432226;  
		$rule13 = {41 41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// inc ecx; inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x4321ec;  
		$rule14 = {90 90 90 90 41 41 41 41 8b ee 8b f7 2b f0 f3 a4 8b f5 e9} 
		// nop ; nop ; nop ; nop ; inc ecx; inc ecx; inc ecx; inc ecx; mov ebp, esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, ebp; jmp 0x4321ec;  
		
	condition:
		pe.is_32bit() and (10 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_ACProtect_v141_no_compress_combined
{
	meta:
		packer="ACProtect"
		generator="PackGenome"
		version="v141"
		config="no_compress"
	strings:
		$rule0 = {83 04 24 06 c3} 
		// add dword ptr [esp], 6; ret ;  
		$rule1 = {83 c4 04 (e9|e8)} 
		// add esp, 4; jmp 0x43043d;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 1 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Obsidium
rule packer_Obsidium_v15_compress_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="compress"
	strings:
		$rule0 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e258;  
		$rule1 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e262;  
		$rule2 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e269;  
		$rule3 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e270;  
		$rule4 = {83 e1 03 (70|71)} 
		// and ecx, 3; jo 0x41e1f6;  
		$rule5 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e27d;  
		$rule6 = {33 d4 (73|72)} 
		// xor edx, esp; jae 0x41e282;  
		$rule7 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e289;  
		$rule8 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e28f;  
		$rule9 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e49a;  
		$rule10 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e49f;  
		$rule11 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e4a7;  
		$rule12 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e4ae;  
		$rule13 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e4b9;  
		$rule14 = {55 eb} 
		// push ebp; jmp 0x41e1f6;  
		$rule15 = {8b ec eb} 
		// mov ebp, esp; jmp 0x41e1fb;  
		$rule16 = {83 ec 08 eb} 
		// sub esp, 8; jmp 0x41e202;  
		$rule17 = {53 eb} 
		// push ebx; jmp 0x41e206;  
		$rule18 = {56 eb} 
		// push esi; jmp 0x41e20c;  
		$rule19 = {57 eb} 
		// push edi; jmp 0x41e210;  
		$rule20 = {89 65 fc eb} 
		// mov dword ptr [ebp - 4], esp; jmp 0x41e216;  
		$rule21 = {8b 45 08 eb} 
		// mov eax, dword ptr [ebp + 8]; jmp 0x41e21e;  
		$rule22 = {8b 58 04 eb} 
		// mov ebx, dword ptr [eax + 4]; jmp 0x41e224;  
		$rule23 = {8b 00 eb} 
		// mov eax, dword ptr [eax]; jmp 0x41e22b;  
		$rule24 = {bf 9a a7 67 02 eb} 
		// mov edi, 0x267a79a; jmp 0x41e235;  
		$rule25 = {c7 45 f8 20 00 00 00 eb} 
		// mov dword ptr [ebp - 8], 0x20; jmp 0x41e40f;  
		$rule26 = {8b 75 0c eb} 
		// mov esi, dword ptr [ebp + 0xc]; jmp 0x41e417;  
		$rule27 = {81 f7 ba 90 88 c4 (73|70)} 
		// xor edi, 0xc48890ba; jae 0x41e420;  
		$rule28 = {8b 55 08 eb} 
		// mov edx, dword ptr [ebp + 8]; jmp 0x41e4d4;  
		$rule29 = {89 02 eb} 
		// mov dword ptr [edx], eax; jmp 0x41e4da;  
		$rule30 = {89 5a 04 eb} 
		// mov dword ptr [edx + 4], ebx; jmp 0x41e4e2;  
		$rule31 = {8b 65 fc eb} 
		// mov esp, dword ptr [ebp - 4]; jmp 0x41e4e8;  
		$rule32 = {5f eb} 
		// pop edi; jmp 0x41e4ec;  
		$rule33 = {5e eb} 
		// pop esi; jmp 0x41e4f2;  
		$rule34 = {5b eb} 
		// pop ebx; jmp 0x41e4f6;  
		$rule35 = {8b e5 eb} 
		// mov esp, ebp; jmp 0x41e4fb;  
		$rule36 = {5d eb} 
		// pop ebp; jmp 0x41e501;  
		$rule37 = {8b 06 eb} 
		// mov eax, dword ptr [esi]; jmp 0x41e50f;  
		$rule38 = {8b 56 04 eb} 
		// mov edx, dword ptr [esi + 4]; jmp 0x41e516;  
		$rule39 = {89 45 f8 eb} 
		// mov dword ptr [ebp - 8], eax; jmp 0x41e51c;  
		$rule40 = {89 55 f4 eb} 
		// mov dword ptr [ebp - 0xc], edx; jmp 0x41e522;  
		$rule41 = {ff 75 10 eb} 
		// push dword ptr [ebp + 0x10]; jmp 0x41e528;  
		$rule42 = {8b 45 fc eb} 
		// mov eax, dword ptr [ebp - 4]; jmp 0x41e617;  
		$rule43 = {31 7e 04 72} 
		// xor dword ptr [esi + 4], edi; jb 0x41e688;  
		$rule44 = {8b 55 f8 eb} 
		// mov edx, dword ptr [ebp - 8]; jmp 0x41e622;  
		$rule45 = {31 06 (73|72)} 
		// xor dword ptr [esi], eax; jae 0x41e627;  
		$rule46 = {8b 7d f4 eb} 
		// mov edi, dword ptr [ebp - 0xc]; jmp 0x41e62e;  
		$rule47 = {89 55 fc eb} 
		// mov dword ptr [ebp - 4], edx; jmp 0x41e635;  
		$rule48 = {83 c6 08 eb} 
		// add esi, 8; jmp 0x41e63c;  
		$rule49 = {83 eb 08 eb} 
		// sub ebx, 8; jmp 0x41e644;  
		
	condition:
		pe.is_32bit() and (35 of them) and (pe.overlay.offset == 0 or for 24 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_remove_exports_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="remove_exports"
	strings:
		$rule0 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e2ea;  
		$rule1 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e369;  
		$rule2 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e36e;  
		$rule3 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e374;  
		$rule4 = {33 d4 (70|71)} 
		// xor edx, esp; jo 0x41e330;  
		$rule5 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e384;  
		$rule6 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e5b2;  
		$rule7 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e5bc;  
		$rule8 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e5c2;  
		$rule9 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e5c8;  
		$rule10 = {83 e1 03 (70|73)} 
		// and ecx, 3; jo 0x41e55a;  
		$rule11 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e5d3;  
		$rule12 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e5e0;  
		$rule13 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e5e6;  
		$rule14 = {55 eb} 
		// push ebp; jmp 0x41e1f3;  
		$rule15 = {8b ec eb} 
		// mov ebp, esp; jmp 0x41e1f9;  
		$rule16 = {83 ec 08 eb} 
		// sub esp, 8; jmp 0x41e1ff;  
		$rule17 = {57 eb} 
		// push edi; jmp 0x41e20c;  
		$rule18 = {89 65 fc eb} 
		// mov dword ptr [ebp - 4], esp; jmp 0x41e213;  
		$rule19 = {8b 45 fc eb} 
		// mov eax, dword ptr [ebp - 4]; jmp 0x41e226;  
		$rule20 = {31 7e 04 (72|70)} 
		// xor dword ptr [esi + 4], edi; jb 0x41e278;  
		$rule21 = {8b 55 f8 eb} 
		// mov edx, dword ptr [ebp - 8]; jmp 0x41e231;  
		$rule22 = {31 06 (70|72)} 
		// xor dword ptr [esi], eax; jo 0x41e269;  
		$rule23 = {8b 7d f4 eb} 
		// mov edi, dword ptr [ebp - 0xc]; jmp 0x41e23b;  
		$rule24 = {89 55 fc eb} 
		// mov dword ptr [ebp - 4], edx; jmp 0x41e242;  
		$rule25 = {83 c6 08 eb} 
		// add esi, 8; jmp 0x41e24a;  
		$rule26 = {83 eb 08 eb} 
		// sub ebx, 8; jmp 0x41e252;  
		$rule27 = {8b 55 08 eb} 
		// mov edx, dword ptr [ebp + 8]; jmp 0x41e26b;  
		$rule28 = {89 02 eb} 
		// mov dword ptr [edx], eax; jmp 0x41e272;  
		$rule29 = {89 5a 04 eb} 
		// mov dword ptr [edx + 4], ebx; jmp 0x41e279;  
		$rule30 = {8b 65 fc eb} 
		// mov esp, dword ptr [ebp - 4]; jmp 0x41e280;  
		$rule31 = {5f eb} 
		// pop edi; jmp 0x41e285;  
		$rule32 = {5e eb} 
		// pop esi; jmp 0x41e289;  
		$rule33 = {5b eb} 
		// pop ebx; jmp 0x41e28e;  
		$rule34 = {8b e5 eb} 
		// mov esp, ebp; jmp 0x41e294;  
		$rule35 = {5d eb} 
		// pop ebp; jmp 0x41e29a;  
		$rule36 = {8b 06 eb} 
		// mov eax, dword ptr [esi]; jmp 0x41e4bc;  
		$rule37 = {8b 56 04 eb} 
		// mov edx, dword ptr [esi + 4]; jmp 0x41e4c3;  
		$rule38 = {89 45 f8 eb} 
		// mov dword ptr [ebp - 8], eax; jmp 0x41e4c9;  
		$rule39 = {89 55 f4 eb} 
		// mov dword ptr [ebp - 0xc], edx; jmp 0x41e4d1;  
		$rule40 = {ff 75 10 eb} 
		// push dword ptr [ebp + 0x10]; jmp 0x41e4d9;  
		$rule41 = {56 eb} 
		// push esi; jmp 0x41e4de;  
		$rule42 = {8b 45 08 eb} 
		// mov eax, dword ptr [ebp + 8]; jmp 0x41e5fc;  
		$rule43 = {8b 58 04 eb} 
		// mov ebx, dword ptr [eax + 4]; jmp 0x41e604;  
		$rule44 = {8b 00 eb} 
		// mov eax, dword ptr [eax]; jmp 0x41e60b;  
		$rule45 = {bf 9a a7 67 02 eb} 
		// mov edi, 0x267a79a; jmp 0x41e613;  
		$rule46 = {c7 45 f8 20 00 00 00 eb} 
		// mov dword ptr [ebp - 8], 0x20; jmp 0x41e61e;  
		$rule47 = {8b 75 0c eb} 
		// mov esi, dword ptr [ebp + 0xc]; jmp 0x41e624;  
		$rule48 = {81 f7 ba 90 88 c4 70} 
		// xor edi, 0xc48890ba; jo 0x41e5d2;  
		
	condition:
		pe.is_32bit() and (34 of them) and (pe.overlay.offset == 0 or for 23 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_protect_api_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="protect_api"
	strings:
		$rule0 = {33 d4 (72|73)} 
		// xor edx, esp; jb 0x41e13b;  
		$rule1 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e43c;  
		$rule2 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e442;  
		$rule3 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e449;  
		$rule4 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e450;  
		$rule5 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e45c;  
		$rule6 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e463;  
		$rule7 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e468;  
		$rule8 = {83 e1 03 (73|72)} 
		// and ecx, 3; jae 0x41e477;  
		$rule9 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e47d;  
		$rule10 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e600;  
		$rule11 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e60b;  
		$rule12 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e62d;  
		$rule13 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e634;  
		
	condition:
		pe.is_32bit() and (9 of them) and (pe.overlay.offset == 0 or for 6 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_full_VM_ENC_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="full_VM_ENC"
	strings:
		$rule0 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e2f1;  
		$rule1 = {33 d4 73} 
		// xor edx, esp; jae 0x41e2f7;  
		$rule2 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e2fd;  
		$rule3 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e308;  
		$rule4 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e30e;  
		$rule5 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e315;  
		$rule6 = {83 e1 03 (70|72)} 
		// and ecx, 3; jo 0x41e2f9;  
		$rule7 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e321;  
		$rule8 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e32a;  
		$rule9 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e331;  
		$rule10 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e427;  
		$rule11 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e42c;  
		$rule12 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e432;  
		$rule13 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e442;  
		$rule14 = {c1 e9 0b eb} 
		// shr ecx, 0xb; jmp 0x41e455;  
		$rule15 = {2b da eb} 
		// sub ebx, edx; jmp 0x41e471;  
		$rule16 = {81 ef ed fe 0b 18 eb} 
		// sub edi, 0x180bfeed; jmp 0x41e47c;  
		$rule17 = {8b d3 eb} 
		// mov edx, ebx; jmp 0x41e483;  
		$rule18 = {8b e3 eb} 
		// mov esp, ebx; jmp 0x41e488;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_runtime_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="runtime"
	strings:
		$rule0 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e137;  
		$rule1 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e13e;  
		$rule2 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e144;  
		$rule3 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e14b;  
		$rule4 = {33 d4 71} 
		// xor edx, esp; jno 0x41e152;  
		$rule5 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e15e;  
		$rule6 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e163;  
		$rule7 = {83 e1 03 (71|73)} 
		// and ecx, 3; jno 0x41e171;  
		$rule8 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e177;  
		$rule9 = {2b da eb} 
		// sub ebx, edx; jmp 0x41e185;  
		$rule10 = {81 ef ed fe 0b 18 eb} 
		// sub edi, 0x180bfeed; jmp 0x41e362;  
		$rule11 = {8b d3 eb} 
		// mov edx, ebx; jmp 0x41e369;  
		$rule12 = {8b e3 eb} 
		// mov esp, ebx; jmp 0x41e370;  
		$rule13 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e389;  
		$rule14 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e392;  
		$rule15 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e3b3;  
		$rule16 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e3ba;  
		$rule17 = {8b 06 eb} 
		// mov eax, dword ptr [esi]; jmp 0x41e195;  
		$rule18 = {8b 56 04 eb} 
		// mov edx, dword ptr [esi + 4]; jmp 0x41e19c;  
		$rule19 = {89 45 f8 eb} 
		// mov dword ptr [ebp - 8], eax; jmp 0x41e1a2;  
		$rule20 = {89 55 f4 eb} 
		// mov dword ptr [ebp - 0xc], edx; jmp 0x41e1aa;  
		$rule21 = {ff 75 10 eb} 
		// push dword ptr [ebp + 0x10]; jmp 0x41e1b0;  
		$rule22 = {56 eb} 
		// push esi; jmp 0x41e1b6;  
		$rule23 = {8b 45 fc eb} 
		// mov eax, dword ptr [ebp - 4]; jmp 0x41e1c3;  
		$rule24 = {31 7e 04 (70|71)} 
		// xor dword ptr [esi + 4], edi; jo 0x41e188;  
		$rule25 = {8b 55 f8 eb} 
		// mov edx, dword ptr [ebp - 8]; jmp 0x41e1ce;  
		$rule26 = {31 06 70} 
		// xor dword ptr [esi], eax; jo 0x41e334;  
		$rule27 = {8b 7d f4 eb} 
		// mov edi, dword ptr [ebp - 0xc]; jmp 0x41e2e0;  
		$rule28 = {89 55 fc eb} 
		// mov dword ptr [ebp - 4], edx; jmp 0x41e2e7;  
		$rule29 = {83 c6 08 eb} 
		// add esi, 8; jmp 0x41e2ed;  
		$rule30 = {83 eb 08 eb} 
		// sub ebx, 8; jmp 0x41e2f3;  
		$rule31 = {bf 9a a7 67 02 eb} 
		// mov edi, 0x267a79a; jmp 0x41e43c;  
		$rule32 = {c7 45 f8 20 00 00 00 eb} 
		// mov dword ptr [ebp - 8], 0x20; jmp 0x41e448;  
		$rule33 = {8b 75 0c eb} 
		// mov esi, dword ptr [ebp + 0xc]; jmp 0x41e44f;  
		$rule34 = {81 f7 ba 90 88 c4 73} 
		// xor edi, 0xc48890ba; jae 0x41e459;  
		$rule35 = {55 eb} 
		// push ebp; jmp 0x41e467;  
		$rule36 = {8b ec eb} 
		// mov ebp, esp; jmp 0x41e46e;  
		$rule37 = {83 ec 08 eb} 
		// sub esp, 8; jmp 0x41e476;  
		$rule38 = {53 eb} 
		// push ebx; jmp 0x41e47b;  
		$rule39 = {57 eb} 
		// push edi; jmp 0x41e486;  
		$rule40 = {89 65 fc eb} 
		// mov dword ptr [ebp - 4], esp; jmp 0x41e48d;  
		$rule41 = {8b 45 08 eb} 
		// mov eax, dword ptr [ebp + 8]; jmp 0x41e495;  
		$rule42 = {8b 58 04 eb} 
		// mov ebx, dword ptr [eax + 4]; jmp 0x41e49d;  
		$rule43 = {8b 00 eb} 
		// mov eax, dword ptr [eax]; jmp 0x41e4a4;  
		$rule44 = {8b 55 08 eb} 
		// mov edx, dword ptr [ebp + 8]; jmp 0x41e4af;  
		$rule45 = {89 02 eb} 
		// mov dword ptr [edx], eax; jmp 0x41e4b6;  
		$rule46 = {89 5a 04 eb} 
		// mov dword ptr [edx + 4], ebx; jmp 0x41e4be;  
		$rule47 = {8b 65 fc eb} 
		// mov esp, dword ptr [ebp - 4]; jmp 0x41e4c4;  
		$rule48 = {5f eb} 
		// pop edi; jmp 0x41e4c9;  
		$rule49 = {5e eb} 
		// pop esi; jmp 0x41e4cd;  
		$rule50 = {5b eb} 
		// pop ebx; jmp 0x41e4d1;  
		$rule51 = {8b e5 eb} 
		// mov esp, ebp; jmp 0x41e4d6;  
		$rule52 = {5d eb} 
		// pop ebp; jmp 0x41e4da;  
		
	condition:
		pe.is_32bit() and (37 of them) and (pe.overlay.offset == 0 or for 25 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_encrypt_resources_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="encrypt_resources"
	strings:
		$rule0 = {33 d4 (73|70)} 
		// xor edx, esp; jae 0x41e321;  
		$rule1 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e326;  
		$rule2 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e331;  
		$rule3 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e337;  
		$rule4 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e33c;  
		$rule5 = {83 e1 03 (72|71)} 
		// and ecx, 3; jb 0x41e2d4;  
		$rule6 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e348;  
		$rule7 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e354;  
		$rule8 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e35c;  
		$rule9 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e47b;  
		$rule10 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e482;  
		$rule11 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e488;  
		$rule12 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e490;  
		$rule13 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e49b;  
		$rule14 = {c1 e9 0b eb} 
		// shr ecx, 0xb; jmp 0x41e583;  
		$rule15 = {2b da eb} 
		// sub ebx, edx; jmp 0x41e59a;  
		$rule16 = {81 ef ed fe 0b 18 eb} 
		// sub edi, 0x180bfeed; jmp 0x41e5a5;  
		$rule17 = {8b d3 eb} 
		// mov edx, ebx; jmp 0x41e5ab;  
		$rule18 = {8b e3 eb} 
		// mov esp, ebx; jmp 0x41e5b1;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Obsidium_v15_delphiBcb_combined
{
	meta:
		packer="Obsidium"
		generator="PackGenome"
		version="v15"
		config="delphiBcb"
	strings:
		$rule0 = {8b d0 eb} 
		// mov edx, eax; jmp 0x41e136;  
		$rule1 = {8b e0 eb} 
		// mov esp, eax; jmp 0x41e13c;  
		$rule2 = {c1 e2 04 eb} 
		// shl edx, 4; jmp 0x41e142;  
		$rule3 = {c1 ec 05 eb} 
		// shr esp, 5; jmp 0x41e148;  
		$rule4 = {33 d4 (72|71)} 
		// xor edx, esp; jb 0x41e0e3;  
		$rule5 = {03 d0 eb} 
		// add edx, eax; jmp 0x41e153;  
		$rule6 = {8b cf eb} 
		// mov ecx, edi; jmp 0x41e15d;  
		$rule7 = {83 e1 03 (70|73)} 
		// and ecx, 3; jo 0x41e12c;  
		$rule8 = {03 24 8e eb} 
		// add esp, dword ptr [esi + ecx*4]; jmp 0x41e172;  
		$rule9 = {2b da eb} 
		// sub ebx, edx; jmp 0x41e181;  
		$rule10 = {81 ef ed fe 0b 18 eb} 
		// sub edi, 0x180bfeed; jmp 0x41e18a;  
		$rule11 = {8b d3 eb} 
		// mov edx, ebx; jmp 0x41e190;  
		$rule12 = {8b e3 eb} 
		// mov esp, ebx; jmp 0x41e196;  
		$rule13 = {03 d3 eb} 
		// add edx, ebx; jmp 0x41e452;  
		$rule14 = {81 ef cc 7a 2b 86 eb} 
		// sub edi, 0x862b7acc; jmp 0x41e45c;  
		$rule15 = {8b e7 eb} 
		// mov esp, edi; jmp 0x41e467;  
		$rule16 = {2b c2 eb} 
		// sub eax, edx; jmp 0x41e480;  
		$rule17 = {ff 4d f8 eb} 
		// dec dword ptr [ebp - 8]; jmp 0x41e486;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Enigma
rule packer_Enigma
{
	meta:
		packer="Enigma"
		generator="PackGenome"
		versions="v42 v155 v31 v38"
	strings:
		$rule0 = {30 10 40 49 0f85} 
		// xor byte ptr [eax], dl; inc eax; dec ecx; jne 0x76acb8;  
		$rule1 = {55 8b ec 83 c4 f0 b8 00 10 40 00 e8} 
		// push ebp; mov ebp, esp; add esp, -0x10; mov eax, 0x401000; call 0x405b6d;  
		$rule2 = {83 c4 10 8b e5 5d e9} 
		// add esp, 0x10; mov esp, ebp; pop ebp; jmp 0x76ac34;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// WinUpack
rule packer_WinUpack_v031_lc6_export_combined
{
	meta:
		packer="WinUpack"
		generator="PackGenome"
		version="v031"
		configs="lc6_export lc6 lc6_relocation"
	strings:
		$rule0 = {50 8b 45 08 52 c1 e8 0b f7 22 8b 55 00 8b 12 0f ca 2b 55 04 3b c2 5a 76} 
		// push eax; mov eax, dword ptr [ebp + 8]; push edx; shr eax, 0xb; mul dword ptr [edx]; mov edx, dword ptr [ebp]; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; cmp eax, edx; pop edx; jbe 0x42764c;  
		$rule1 = {89 45 08 33 c0 b4 08 2b 02 c1 e8 05 01 02 eb} 
		// mov dword ptr [ebp + 8], eax; xor eax, eax; mov ah, 8; sub eax, dword ptr [edx]; shr eax, 5; add dword ptr [edx], eax; jmp 0x42765a;  
		$rule2 = {58 9c 80 7d 0b 00 75} 
		// pop eax; pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x42766d;  
		$rule3 = {01 45 04 29 45 08 8b 02 c1 e8 05 29 02 f9 58 9c 80 7d 0b 00 75} 
		// add dword ptr [ebp + 4], eax; sub dword ptr [ebp + 8], eax; mov eax, dword ptr [edx]; shr eax, 5; sub dword ptr [edx], eax; stc ; pop eax; pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x42766d;  
		$rule4 = {8a 07 47 04 18 3c 02 73} 
		// mov al, byte ptr [edi]; inc edi; add al, 0x18; cmp al, 2; jae 0x4275d9;  
		$rule5 = {ff 45 00 c1 65 04 08 c1 65 08 08 9d c3} 
		// inc dword ptr [ebp]; shl dword ptr [ebp + 4], 8; shl dword ptr [ebp + 8], 8; popfd ; ret ;  
		$rule6 = {9c 80 7d 0b 00 75} 
		// pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x42766d;  
		$rule7 = {8b 55 00 d1 6d 08 8b 12 0f ca 2b 55 04 03 c0 3b 55 08 72} 
		// mov edx, dword ptr [ebp]; shr dword ptr [ebp + 8], 1; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; add eax, eax; cmp edx, dword ptr [ebp + 8]; jb 0x427592;  
		$rule8 = {d1 e8 13 d2 } 
		// shr eax, 1; adc edx, edx; loop 0x4275b0;  
		$rule9 = {aa 3b 7e 2c 73} 
		// stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4275d2;  
		$rule10 = {50 0f b6 5f ff c1 e3 06 b3 00 8d 1c 5b 8d 9c 9d 0c 10 00 00 b0 01 e3} 
		// push eax; movzx ebx, byte ptr [edi - 1]; shl ebx, 6; mov bl, 0; lea ebx, [ebx + ebx*2]; lea ebx, [ebp + ebx*4 + 0x100c]; mov al, 1; jecxz 0x4274c0;  
		$rule11 = {8b 55 08 40 01 55 04 ff} 
		// mov edx, dword ptr [ebp + 8]; inc eax; add dword ptr [ebp + 4], edx; call dword ptr [esi + 0x10];  
		$rule12 = {b1 30 8b 5d 0c 03 d1 ff} 
		// mov cl, 0x30; mov ebx, dword ptr [ebp + 0xc]; add edx, ecx; call dword ptr [esi];  
		$rule13 = {8b d7 2b 55 0c 8a 2a 33 d2 84 e9 0f 95 c6 52 fe c6 8a d0 8d 14 93 ff} 
		// mov edx, edi; sub edx, dword ptr [ebp + 0xc]; mov ch, byte ptr [edx]; xor edx, edx; test cl, ch; setne dh; push edx; inc dh; mov dl, al; lea edx, [ebx + edx*4]; call dword ptr [esi];  
		$rule14 = {b0 00 3c 07 72} 
		// mov al, 0; cmp al, 7; jb 0x42747f;  
		$rule15 = {3c 04 8b d8 72} 
		// cmp al, 4; mov ebx, eax; jb 0x4275b9;  
		$rule16 = {33 db d1 e8 13 db 48 43 91 43 d3 e3 80 f9 05 8d 94 9d 7c 01 00 00 76} 
		// xor ebx, ebx; shr eax, 1; adc ebx, ebx; dec eax; inc ebx; xchg eax, ecx; inc ebx; shl ebx, cl; cmp cl, 5; lea edx, [ebp + ebx*4 + 0x17c]; jbe 0x4275a0;  
		$rule17 = {33 d2 59 d1 e8 13 d2 } 
		// xor edx, edx; pop ecx; shr eax, 1; adc edx, edx; loop 0x4275b0;  
		$rule18 = {5b 03 da 43 59 89 5d 0c 56 8b f7 2b f3 f3 a4 ac 5e b1 80 aa 3b 7e 2c 73} 
		// pop ebx; add ebx, edx; inc ebx; pop ecx; mov dword ptr [ebp + 0xc], ebx; push esi; mov esi, edi; sub esi, ebx; rep movsb byte ptr es:[edi], byte ptr [esi]; lodsb al, byte ptr [esi]; pop esi; mov cl, 0x80; stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4275d2;  
		$rule19 = {80 e9 04 33 c0 8b 55 00 d1 6d 08 8b 12 0f ca 2b 55 04 03 c0 3b 55 08 72} 
		// sub cl, 4; xor eax, eax; mov edx, dword ptr [ebp]; shr dword ptr [ebp + 8], 1; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; add eax, eax; cmp edx, dword ptr [ebp + 8]; jb 0x427592;  
		$rule20 = {b1 04 d3 e0 03 d8 8d 55 1c 33 c0 53 40 51 d3 e0 8b da 91 ff} 
		// mov cl, 4; shl eax, cl; add ebx, eax; lea edx, [ebp + 0x1c]; xor eax, eax; push ebx; inc eax; push ecx; shl eax, cl; mov ebx, edx; xchg eax, ecx; call dword ptr [esi + 4];  
		$rule21 = {89 5d 0c 56 8b f7 2b f3 f3 a4 ac 5e b1 80 aa 3b 7e 2c 73} 
		// mov dword ptr [ebp + 0xc], ebx; push esi; mov esi, edi; sub esi, ebx; rep movsb byte ptr es:[edi], byte ptr [esi]; lodsb al, byte ptr [esi]; pop esi; mov cl, 0x80; stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4275d2;  
		$rule22 = {3c 07 b0 08 72} 
		// cmp al, 7; mov al, 8; jb 0x427512;  
		$rule23 = {50 53 8b d5 03 56 14 ff} 
		// push eax; push ebx; mov edx, ebp; add edx, dword ptr [esi + 0x14]; call dword ptr [esi + 0xc];  
		$rule24 = {33 c0 53 40 51 d3 e0 8b da 91 ff} 
		// xor eax, eax; push ebx; inc eax; push ecx; shl eax, cl; mov ebx, edx; xchg eax, ecx; call dword ptr [esi + 4];  
		$rule25 = {2c 03 50 0f b6 5f ff c1 e3 06 b3 00 8d 1c 5b 8d 9c 9d 0c 10 00 00 b0 01 e3} 
		// sub al, 3; push eax; movzx ebx, byte ptr [edi - 1]; shl ebx, 6; mov bl, 0; lea ebx, [ebx + ebx*2]; lea ebx, [ebp + ebx*4 + 0x100c]; mov al, 1; jecxz 0x4274c0;  
		
	condition:
		pe.is_32bit() and (18 of them) and (pe.overlay.offset == 0 or for 12 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_WinUpack_v031_lc0_combined
{
	meta:
		packer="WinUpack"
		generator="PackGenome"
		version="v031"
		config="lc0"
	strings:
		$rule0 = {50 8b 45 08 52 c1 e8 0b f7 22 8b 55 00 8b 12 0f ca 2b 55 04 3b c2 5a 76} 
		// push eax; mov eax, dword ptr [ebp + 8]; push edx; shr eax, 0xb; mul dword ptr [edx]; mov edx, dword ptr [ebp]; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; cmp eax, edx; pop edx; jbe 0x42753f;  
		$rule1 = {89 45 08 33 c0 b4 08 2b 02 c1 e8 05 01 02 eb} 
		// mov dword ptr [ebp + 8], eax; xor eax, eax; mov ah, 8; sub eax, dword ptr [edx]; shr eax, 5; add dword ptr [edx], eax; jmp 0x42754d;  
		$rule2 = {58 9c 80 7d 0b 00 75} 
		// pop eax; pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x427560;  
		$rule3 = {01 45 04 29 45 08 8b 02 c1 e8 05 29 02 f9 58 9c 80 7d 0b 00 75} 
		// add dword ptr [ebp + 4], eax; sub dword ptr [ebp + 8], eax; mov eax, dword ptr [edx]; shr eax, 5; sub dword ptr [edx], eax; stc ; pop eax; pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x427560;  
		$rule4 = {8a 07 47 04 18 3c 02 73} 
		// mov al, byte ptr [edi]; inc edi; add al, 0x18; cmp al, 2; jae 0x4274cc;  
		$rule5 = {ff 45 00 c1 65 04 08 c1 65 08 08 9d c3} 
		// inc dword ptr [ebp]; shl dword ptr [ebp + 4], 8; shl dword ptr [ebp + 8], 8; popfd ; ret ;  
		$rule6 = {9c 80 7d 0b 00 75} 
		// pushfd ; cmp byte ptr [ebp + 0xb], 0; jne 0x427560;  
		$rule7 = {8b 55 00 d1 6d 08 8b 12 0f ca 2b 55 04 03 c0 3b 55 08 72} 
		// mov edx, dword ptr [ebp]; shr dword ptr [ebp + 8], 1; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; add eax, eax; cmp edx, dword ptr [ebp + 8]; jb 0x427485;  
		$rule8 = {d1 e8 13 d2 } 
		// shr eax, 1; adc edx, edx; loop 0x4274a3;  
		$rule9 = {aa 3b 7e 2c 73} 
		// stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4274c5;  
		$rule10 = {50 0f b6 5f ff c1 e3 00 b3 00 8d 1c 5b 8d 9c 9d 0c 10 00 00 b0 01 e3} 
		// push eax; movzx ebx, byte ptr [edi - 1]; shl ebx, 0; mov bl, 0; lea ebx, [ebx + ebx*2]; lea ebx, [ebp + ebx*4 + 0x100c]; mov al, 1; jecxz 0x4273b3;  
		$rule11 = {8b 55 08 40 01 55 04 ff} 
		// mov edx, dword ptr [ebp + 8]; inc eax; add dword ptr [ebp + 4], edx; call dword ptr [esi + 0x10];  
		$rule12 = {b1 30 8b 5d 0c 03 d1 ff} 
		// mov cl, 0x30; mov ebx, dword ptr [ebp + 0xc]; add edx, ecx; call dword ptr [esi];  
		$rule13 = {b0 00 3c 07 72} 
		// mov al, 0; cmp al, 7; jb 0x427372;  
		$rule14 = {8b d7 2b 55 0c 8a 2a 33 d2 84 e9 0f 95 c6 52 fe c6 8a d0 8d 14 93 ff} 
		// mov edx, edi; sub edx, dword ptr [ebp + 0xc]; mov ch, byte ptr [edx]; xor edx, edx; test cl, ch; setne dh; push edx; inc dh; mov dl, al; lea edx, [ebx + edx*4]; call dword ptr [esi];  
		$rule15 = {3c 04 8b d8 72} 
		// cmp al, 4; mov ebx, eax; jb 0x4274ac;  
		$rule16 = {33 db d1 e8 13 db 48 43 91 43 d3 e3 80 f9 05 8d 94 9d 7c 01 00 00 76} 
		// xor ebx, ebx; shr eax, 1; adc ebx, ebx; dec eax; inc ebx; xchg eax, ecx; inc ebx; shl ebx, cl; cmp cl, 5; lea edx, [ebp + ebx*4 + 0x17c]; jbe 0x427493;  
		$rule17 = {33 d2 59 d1 e8 13 d2 } 
		// xor edx, edx; pop ecx; shr eax, 1; adc edx, edx; loop 0x4274a3;  
		$rule18 = {5b 03 da 43 59 89 5d 0c 56 8b f7 2b f3 f3 a4 ac 5e b1 80 aa 3b 7e 2c 73} 
		// pop ebx; add ebx, edx; inc ebx; pop ecx; mov dword ptr [ebp + 0xc], ebx; push esi; mov esi, edi; sub esi, ebx; rep movsb byte ptr es:[edi], byte ptr [esi]; lodsb al, byte ptr [esi]; pop esi; mov cl, 0x80; stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4274c5;  
		$rule19 = {80 e9 04 33 c0 8b 55 00 d1 6d 08 8b 12 0f ca 2b 55 04 03 c0 3b 55 08 72} 
		// sub cl, 4; xor eax, eax; mov edx, dword ptr [ebp]; shr dword ptr [ebp + 8], 1; mov edx, dword ptr [edx]; bswap edx; sub edx, dword ptr [ebp + 4]; add eax, eax; cmp edx, dword ptr [ebp + 8]; jb 0x427485;  
		$rule20 = {b1 04 d3 e0 03 d8 8d 55 1c 33 c0 53 40 51 d3 e0 8b da 91 ff} 
		// mov cl, 4; shl eax, cl; add ebx, eax; lea edx, [ebp + 0x1c]; xor eax, eax; push ebx; inc eax; push ecx; shl eax, cl; mov ebx, edx; xchg eax, ecx; call dword ptr [esi + 4];  
		$rule21 = {89 5d 0c 56 8b f7 2b f3 f3 a4 ac 5e b1 80 aa 3b 7e 2c 73} 
		// mov dword ptr [ebp + 0xc], ebx; push esi; mov esi, edi; sub esi, ebx; rep movsb byte ptr es:[edi], byte ptr [esi]; lodsb al, byte ptr [esi]; pop esi; mov cl, 0x80; stosb byte ptr es:[edi], al; cmp edi, dword ptr [esi + 0x2c]; jae 0x4274c5;  
		$rule22 = {3c 07 b0 08 72} 
		// cmp al, 7; mov al, 8; jb 0x427405;  
		$rule23 = {50 53 8b d5 03 56 14 ff} 
		// push eax; push ebx; mov edx, ebp; add edx, dword ptr [esi + 0x14]; call dword ptr [esi + 0xc];  
		$rule24 = {33 c0 53 40 51 d3 e0 8b da 91 ff} 
		// xor eax, eax; push ebx; inc eax; push ecx; shl eax, cl; mov ebx, edx; xchg eax, ecx; call dword ptr [esi + 4];  
		$rule25 = {2c 03 50 0f b6 5f ff c1 e3 00 b3 00 8d 1c 5b 8d 9c 9d 0c 10 00 00 b0 01 e3} 
		// sub al, 3; push eax; movzx ebx, byte ptr [edi - 1]; shl ebx, 0; mov bl, 0; lea ebx, [ebx + ebx*2]; lea ebx, [ebp + ebx*4 + 0x100c]; mov al, 1; jecxz 0x4273b3;  
		
	condition:
		pe.is_32bit() and (18 of them) and (pe.overlay.offset == 0 or for 12 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// ASPack
rule packer_ASPack_v229
{
	meta:
		packer="ASPack"
		generator="PackGenome"
		versions="v229"
	strings:
		$rule0 = {8b d0 2b d1 40 8a 12 88 50 ff 8b 16 3b c2 72} 
		// mov edx, eax; sub edx, ecx; inc eax; mov dl, byte ptr [edx]; mov byte ptr [eax - 1], dl; mov edx, dword ptr [esi]; cmp eax, edx; jb 0x41bf47;  
		$rule1 = {ac 3c e8 74} 
		// lodsb al, byte ptr [esi]; cmp al, 0xe8; je 0x41b134;  
		$rule2 = {43 49 eb} 
		// inc ebx; dec ecx; jmp 0x41b11f;  
		$rule3 = {51 53 56 8b f1 57 8b 06 83 78 04 08 72} 
		// push ecx; push ebx; push esi; mov esi, ecx; push edi; mov eax, dword ptr [esi]; cmp dword ptr [eax + 4], 8; jb 0x41b9ee;  
		$rule4 = {8b 50 04 8b 40 08 b9 08 00 00 00 2b ca d3 e8 8b 4e 24 25 00 fe ff 00 3b c1 73} 
		// mov edx, dword ptr [eax + 4]; mov eax, dword ptr [eax + 8]; mov ecx, 8; sub ecx, edx; shr eax, cl; mov ecx, dword ptr [esi + 0x24]; and eax, 0xfffe00; cmp eax, ecx; jae 0x41ba1d;  
		$rule5 = {8b 0e 8b 79 04 03 fa 89 79 04 8b 1c 96 b9 18 00 00 00 2b c3 2b ca 5f d3 e8 8b 4c 96 44 03 c1 8b 8e 88 00 00 00 5e 5b 8b 04 81 59 c3} 
		// mov ecx, dword ptr [esi]; mov edi, dword ptr [ecx + 4]; add edi, edx; mov dword ptr [ecx + 4], edi; mov ebx, dword ptr [esi + edx*4]; mov ecx, 0x18; sub eax, ebx; sub ecx, edx; pop edi; shr eax, cl; mov ecx, dword ptr [esi + edx*4 + 0x44]; add eax, ecx; mov ecx, dword ptr [esi + 0x88]; pop esi; pop ebx; mov eax, dword ptr [ecx + eax*4]; pop ecx; ret ;  
		$rule6 = {8b 08 8a 11 41 88 54 24 0c 89 08 8b 48 08 8b 54 24 0c c1 e1 08 81 e2 ff 00 00 00 0b ca 8b 50 04 83 c2 f8 89 48 08 8b ca 89 50 04 83 f9 08 73} 
		// mov ecx, dword ptr [eax]; mov dl, byte ptr [ecx]; inc ecx; mov byte ptr [esp + 0xc], dl; mov dword ptr [eax], ecx; mov ecx, dword ptr [eax + 8]; mov edx, dword ptr [esp + 0xc]; shl ecx, 8; and edx, 0xff; or ecx, edx; mov edx, dword ptr [eax + 4]; add edx, -8; mov dword ptr [eax + 8], ecx; mov ecx, edx; mov dword ptr [eax + 4], edx; cmp ecx, 8; jae 0x41b9be;  
		$rule7 = {8b 96 8c 00 00 00 8b c8 c1 e9 10 33 db 8a 1c 11 8b d3 eb} 
		// mov edx, dword ptr [esi + 0x8c]; mov ecx, eax; shr ecx, 0x10; xor ebx, ebx; mov bl, byte ptr [ecx + edx]; mov edx, ebx; jmp 0x41ba58;  
		$rule8 = {8b 0e 88 01 8b 0e 41 47 89 0e 89 7c 24 10 e9} 
		// mov ecx, dword ptr [esi]; mov byte ptr [ecx], al; mov ecx, dword ptr [esi]; inc ecx; inc edi; mov dword ptr [esi], ecx; mov dword ptr [esp + 0x10], edi; jmp 0x41bf70;  
		$rule9 = {5e 81 ee 5f ba 46 00 c3} 
		// pop esi; sub esi, 0x46ba5f; ret ;  
		$rule10 = {05 00 ff ff ff 8b e8 83 e0 07 c1 ed 03 8d 50 02 83 f8 07 89 54 24 14 0f85} 
		// add eax, 0xffffff00; mov ebp, eax; and eax, 7; shr ebp, 3; lea edx, [eax + 2]; cmp eax, 7; mov dword ptr [esp + 0x14], edx; jne 0x41be03;  
		$rule11 = {8a 94 35 d2 b4 46 00 5e 84 c0 8b fa 74} 
		// mov dl, byte ptr [ebp + esi + 0x46b4d2]; pop esi; test al, al; mov edi, edx; je 0x41be9c;  
		$rule12 = {8b 44 24 10 03 c7 89 44 24 10 8b f8 eb} 
		// mov eax, dword ptr [esp + 0x10]; add eax, edi; mov dword ptr [esp + 0x10], eax; mov edi, eax; jmp 0x41bf70;  
		$rule13 = {3b 46 28 1b d2 83 c2 0a eb} 
		// cmp eax, dword ptr [esi + 0x28]; sbb edx, edx; add edx, 0xa; jmp 0x41ba58;  
		$rule14 = {8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcf2;  
		$rule15 = {8b 56 08 8b 46 0c b9 08 00 00 00 2b ca 03 d7 d3 e8 b9 18 00 00 00 89 56 08 2b cf 25 ff ff ff 00 d3 e8 03 d8 83 fb 03 73} 
		// mov edx, dword ptr [esi + 8]; mov eax, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edx; add edx, edi; shr eax, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edx; sub ecx, edi; and eax, 0xffffff; shr eax, cl; add ebx, eax; cmp ebx, 3; jae 0x41bf16;  
		$rule16 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 20 8b 4e 08 89 46 04 8b 44 24 20 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x20], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x20]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41bea2;  
		$rule17 = {8b 86 54 02 00 00 8b 96 50 02 00 00 8d 4b fd 89 86 58 02 00 00 89 96 54 02 00 00 89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi + 0x254]; mov edx, dword ptr [esi + 0x250]; lea ecx, [ebx - 3]; mov dword ptr [esi + 0x258], eax; mov dword ptr [esi + 0x254], edx; mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		$rule18 = {8b 8c 9e 50 02 00 00 85 db 74} 
		// mov ecx, dword ptr [esi + ebx*4 + 0x250]; test ebx, ebx; je 0x41bf37;  
		$rule19 = {8b 8b 60 02 00 00 8a 14 31 02 d0 80 e2 0f 88 54 34 24 46 eb} 
		// mov ecx, dword ptr [ebx + 0x260]; mov dl, byte ptr [ecx + esi]; add dl, al; and dl, 0xf; mov byte ptr [esp + esi + 0x24], dl; inc esi; jmp 0x41bc46;  
		$rule20 = {8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		$rule21 = {c6 44 34 24 00 46 48 85 c0 7f} 
		// mov byte ptr [esp + esi + 0x24], 0; inc esi; dec eax; test eax, eax; jg 0x41bc33;  
		$rule22 = {8b 46 08 8d 6f fd 83 f8 08 72} 
		// mov eax, dword ptr [esi + 8]; lea ebp, [edi - 3]; cmp eax, 8; jb 0x41be67;  
		$rule23 = {8b 46 08 8b 7e 0c b9 08 00 00 00 2b c8 03 c5 d3 ef b9 18 00 00 00 89 46 08 2b cd 81 e7 ff ff ff 00 d3 ef 8d 8e 30 01 00 00 e8} 
		// mov eax, dword ptr [esi + 8]; mov edi, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, eax; add eax, ebp; shr edi, cl; mov ecx, 0x18; mov dword ptr [esi + 8], eax; sub ecx, ebp; and edi, 0xffffff; shr edi, cl; lea ecx, [esi + 0x130]; call 0x41b9b0;  
		$rule24 = {03 c3 8d 1c f8 eb} 
		// add eax, ebx; lea ebx, [eax + edi*8]; jmp 0x41bef7;  
		$rule25 = {24 00 c1 c0 18 2b c3 89 06 83 c3 05 83 c6 04 83 e9 05 eb} 
		// and al, 0; rol eax, 0x18; sub eax, ebx; mov dword ptr [esi], eax; add ebx, 5; add esi, 4; sub ecx, 5; jmp 0x41b11f;  
		$rule26 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 1c 8b 4e 08 89 46 04 8b 44 24 1c 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x1c], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x1c]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41be36;  
		$rule27 = {8b 4e 08 33 db 56 e8} 
		// mov ecx, dword ptr [esi + 8]; xor ebx, ebx; push esi; call 0x41bcf2;  
		$rule28 = {8a 9c 30 b6 b4 46 00 5e 83 f9 08 72} 
		// mov bl, byte ptr [eax + esi + 0x46b4b6]; pop esi; cmp ecx, 8; jb 0x41bdc4;  
		$rule29 = {8b 7e 08 8b 56 0c b9 08 00 00 00 2b cf 03 fb d3 ea b9 18 00 00 00 89 7e 08 2b cb 81 e2 ff ff ff 00 d3 ea 33 c9 56 e8} 
		// mov edi, dword ptr [esi + 8]; mov edx, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edi; add edi, ebx; shr edx, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edi; sub ecx, ebx; and edx, 0xffffff; shr edx, cl; xor ecx, ecx; push esi; call 0x41bcf2;  
		$rule30 = {8a 8c 30 9a b4 46 00 5e 8b 44 24 14 03 ca 03 c1 89 44 24 14 8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov cl, byte ptr [eax + esi + 0x46b49a]; pop esi; mov eax, dword ptr [esp + 0x14]; add ecx, edx; add eax, ecx; mov dword ptr [esp + 0x14], eax; mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcf2;  
		$rule31 = {8b 96 50 02 00 00 89 94 9e 50 02 00 00 eb} 
		// mov edx, dword ptr [esi + 0x250]; mov dword ptr [esi + ebx*4 + 0x250], edx; jmp 0x41bf31;  
		$rule32 = {89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		
	condition:
		pe.is_32bit() and (23 of them) and (pe.overlay.offset == 0 or for 16 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_ASPack_v238
{
	meta:
		packer="ASPack"
		generator="PackGenome"
		versions="v238"
	strings:
		$rule0 = {8b d0 2b d1 40 8a 12 88 50 ff 8b 16 3b c2 72} 
		// mov edx, eax; sub edx, ecx; inc eax; mov dl, byte ptr [edx]; mov byte ptr [eax - 1], dl; mov edx, dword ptr [esi]; cmp eax, edx; jb 0x41bf47;  
		$rule1 = {ac 3c e8 74} 
		// lodsb al, byte ptr [esi]; cmp al, 0xe8; je 0x41b134;  
		$rule2 = {43 49 eb} 
		// inc ebx; dec ecx; jmp 0x41b11f;  
		$rule3 = {51 53 56 8b f1 57 8b 06 83 78 04 08 72} 
		// push ecx; push ebx; push esi; mov esi, ecx; push edi; mov eax, dword ptr [esi]; cmp dword ptr [eax + 4], 8; jb 0x41b9ee;  
		$rule4 = {8b 50 04 8b 40 08 b9 08 00 00 00 2b ca d3 e8 8b 4e 24 25 00 fe ff 00 3b c1 73} 
		// mov edx, dword ptr [eax + 4]; mov eax, dword ptr [eax + 8]; mov ecx, 8; sub ecx, edx; shr eax, cl; mov ecx, dword ptr [esi + 0x24]; and eax, 0xfffe00; cmp eax, ecx; jae 0x41ba1d;  
		$rule5 = {8b 0e 8b 79 04 03 fa 89 79 04 8b 1c 96 b9 18 00 00 00 2b c3 2b ca 5f d3 e8 8b 4c 96 44 03 c1 8b 8e 88 00 00 00 5e 5b 8b 04 81 59 c3} 
		// mov ecx, dword ptr [esi]; mov edi, dword ptr [ecx + 4]; add edi, edx; mov dword ptr [ecx + 4], edi; mov ebx, dword ptr [esi + edx*4]; mov ecx, 0x18; sub eax, ebx; sub ecx, edx; pop edi; shr eax, cl; mov ecx, dword ptr [esi + edx*4 + 0x44]; add eax, ecx; mov ecx, dword ptr [esi + 0x88]; pop esi; pop ebx; mov eax, dword ptr [ecx + eax*4]; pop ecx; ret ;  
		$rule6 = {8b 08 8a 11 41 88 54 24 0c 89 08 8b 48 08 8b 54 24 0c c1 e1 08 81 e2 ff 00 00 00 0b ca 8b 50 04 83 c2 f8 89 48 08 8b ca 89 50 04 83 f9 08 73} 
		// mov ecx, dword ptr [eax]; mov dl, byte ptr [ecx]; inc ecx; mov byte ptr [esp + 0xc], dl; mov dword ptr [eax], ecx; mov ecx, dword ptr [eax + 8]; mov edx, dword ptr [esp + 0xc]; shl ecx, 8; and edx, 0xff; or ecx, edx; mov edx, dword ptr [eax + 4]; add edx, -8; mov dword ptr [eax + 8], ecx; mov ecx, edx; mov dword ptr [eax + 4], edx; cmp ecx, 8; jae 0x41b9be;  
		$rule7 = {8b 96 8c 00 00 00 8b c8 c1 e9 10 33 db 8a 1c 11 8b d3 eb} 
		// mov edx, dword ptr [esi + 0x8c]; mov ecx, eax; shr ecx, 0x10; xor ebx, ebx; mov bl, byte ptr [ecx + edx]; mov edx, ebx; jmp 0x41ba58;  
		$rule8 = {8b 0e 88 01 8b 0e 41 47 89 0e 89 7c 24 10 e9} 
		// mov ecx, dword ptr [esi]; mov byte ptr [ecx], al; mov ecx, dword ptr [esi]; inc ecx; inc edi; mov dword ptr [esi], ecx; mov dword ptr [esp + 0x10], edi; jmp 0x41bf70;  
		$rule9 = {5e 81 ee 5f ca 46 00 c3} 
		// pop esi; sub esi, 0x46ca5f; ret ;  
		$rule10 = {05 00 ff ff ff 8b e8 83 e0 07 c1 ed 03 8d 50 02 83 f8 07 89 54 24 14 0f85} 
		// add eax, 0xffffff00; mov ebp, eax; and eax, 7; shr ebp, 3; lea edx, [eax + 2]; cmp eax, 7; mov dword ptr [esp + 0x14], edx; jne 0x41be03;  
		$rule11 = {8a 94 35 d2 c4 46 00 5e 84 c0 8b fa 74} 
		// mov dl, byte ptr [ebp + esi + 0x46c4d2]; pop esi; test al, al; mov edi, edx; je 0x41be9c;  
		$rule12 = {8b 44 24 10 03 c7 89 44 24 10 8b f8 eb} 
		// mov eax, dword ptr [esp + 0x10]; add eax, edi; mov dword ptr [esp + 0x10], eax; mov edi, eax; jmp 0x41bf70;  
		$rule13 = {3b 46 28 1b d2 83 c2 0a eb} 
		// cmp eax, dword ptr [esi + 0x28]; sbb edx, edx; add edx, 0xa; jmp 0x41ba58;  
		$rule14 = {8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcf2;  
		$rule15 = {8b 56 08 8b 46 0c b9 08 00 00 00 2b ca 03 d7 d3 e8 b9 18 00 00 00 89 56 08 2b cf 25 ff ff ff 00 d3 e8 03 d8 83 fb 03 73} 
		// mov edx, dword ptr [esi + 8]; mov eax, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edx; add edx, edi; shr eax, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edx; sub ecx, edi; and eax, 0xffffff; shr eax, cl; add ebx, eax; cmp ebx, 3; jae 0x41bf16;  
		$rule16 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 20 8b 4e 08 89 46 04 8b 44 24 20 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x20], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x20]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41bea2;  
		$rule17 = {8b 86 54 02 00 00 8b 96 50 02 00 00 8d 4b fd 89 86 58 02 00 00 89 96 54 02 00 00 89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi + 0x254]; mov edx, dword ptr [esi + 0x250]; lea ecx, [ebx - 3]; mov dword ptr [esi + 0x258], eax; mov dword ptr [esi + 0x254], edx; mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		$rule18 = {8b 8c 9e 50 02 00 00 85 db 74} 
		// mov ecx, dword ptr [esi + ebx*4 + 0x250]; test ebx, ebx; je 0x41bf37;  
		$rule19 = {8b 8b 60 02 00 00 8a 14 31 02 d0 80 e2 0f 88 54 34 24 46 eb} 
		// mov ecx, dword ptr [ebx + 0x260]; mov dl, byte ptr [ecx + esi]; add dl, al; and dl, 0xf; mov byte ptr [esp + esi + 0x24], dl; inc esi; jmp 0x41bc46;  
		$rule20 = {8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		$rule21 = {c6 44 34 24 00 46 48 85 c0 7f} 
		// mov byte ptr [esp + esi + 0x24], 0; inc esi; dec eax; test eax, eax; jg 0x41bc33;  
		$rule22 = {8b 46 08 8d 6f fd 83 f8 08 72} 
		// mov eax, dword ptr [esi + 8]; lea ebp, [edi - 3]; cmp eax, 8; jb 0x41be67;  
		$rule23 = {8b 46 08 8b 7e 0c b9 08 00 00 00 2b c8 03 c5 d3 ef b9 18 00 00 00 89 46 08 2b cd 81 e7 ff ff ff 00 d3 ef 8d 8e 30 01 00 00 e8} 
		// mov eax, dword ptr [esi + 8]; mov edi, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, eax; add eax, ebp; shr edi, cl; mov ecx, 0x18; mov dword ptr [esi + 8], eax; sub ecx, ebp; and edi, 0xffffff; shr edi, cl; lea ecx, [esi + 0x130]; call 0x41b9b0;  
		$rule24 = {03 c3 8d 1c f8 eb} 
		// add eax, ebx; lea ebx, [eax + edi*8]; jmp 0x41bef7;  
		$rule25 = {24 00 c1 c0 18 2b c3 89 06 83 c3 05 83 c6 04 83 e9 05 eb} 
		// and al, 0; rol eax, 0x18; sub eax, ebx; mov dword ptr [esi], eax; add ebx, 5; add esi, 4; sub ecx, 5; jmp 0x41b11f;  
		$rule26 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 1c 8b 4e 08 89 46 04 8b 44 24 1c 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x1c], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x1c]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41be36;  
		$rule27 = {8b 4e 08 33 db 56 e8} 
		// mov ecx, dword ptr [esi + 8]; xor ebx, ebx; push esi; call 0x41bcf2;  
		$rule28 = {8a 9c 30 b6 c4 46 00 5e 83 f9 08 72} 
		// mov bl, byte ptr [eax + esi + 0x46c4b6]; pop esi; cmp ecx, 8; jb 0x41bdc4;  
		$rule29 = {8b 7e 08 8b 56 0c b9 08 00 00 00 2b cf 03 fb d3 ea b9 18 00 00 00 89 7e 08 2b cb 81 e2 ff ff ff 00 d3 ea 33 c9 56 e8} 
		// mov edi, dword ptr [esi + 8]; mov edx, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edi; add edi, ebx; shr edx, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edi; sub ecx, ebx; and edx, 0xffffff; shr edx, cl; xor ecx, ecx; push esi; call 0x41bcf2;  
		$rule30 = {8a 8c 30 9a c4 46 00 5e 8b 44 24 14 03 ca 03 c1 89 44 24 14 8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov cl, byte ptr [eax + esi + 0x46c49a]; pop esi; mov eax, dword ptr [esp + 0x14]; add ecx, edx; add eax, ecx; mov dword ptr [esp + 0x14], eax; mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcf2;  
		$rule31 = {8b 96 50 02 00 00 89 94 9e 50 02 00 00 eb} 
		// mov edx, dword ptr [esi + 0x250]; mov dword ptr [esi + ebx*4 + 0x250], edx; jmp 0x41bf31;  
		$rule32 = {89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf57;  
		
	condition:
		pe.is_32bit() and (23 of them) and (pe.overlay.offset == 0 or for 16 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_ASPack_v242
{
	meta:
		packer="ASPack"
		generator="PackGenome"
		versions="v242"
	strings:
		$rule0 = {8b d0 2b d1 40 8a 12 88 50 ff 8b 16 3b c2 72} 
		// mov edx, eax; sub edx, ecx; inc eax; mov dl, byte ptr [edx]; mov byte ptr [eax - 1], dl; mov edx, dword ptr [esi]; cmp eax, edx; jb 0x41bf53;  
		$rule1 = {ac 3c e8 74} 
		// lodsb al, byte ptr [esi]; cmp al, 0xe8; je 0x41b140;  
		$rule2 = {43 49 eb} 
		// inc ebx; dec ecx; jmp 0x41b12b;  
		$rule3 = {51 53 56 8b f1 57 8b 06 83 78 04 08 72} 
		// push ecx; push ebx; push esi; mov esi, ecx; push edi; mov eax, dword ptr [esi]; cmp dword ptr [eax + 4], 8; jb 0x41b9fa;  
		$rule4 = {8b 50 04 8b 40 08 b9 08 00 00 00 2b ca d3 e8 8b 4e 24 25 00 fe ff 00 3b c1 73} 
		// mov edx, dword ptr [eax + 4]; mov eax, dword ptr [eax + 8]; mov ecx, 8; sub ecx, edx; shr eax, cl; mov ecx, dword ptr [esi + 0x24]; and eax, 0xfffe00; cmp eax, ecx; jae 0x41ba29;  
		$rule5 = {8b 0e 8b 79 04 03 fa 89 79 04 8b 1c 96 b9 18 00 00 00 2b c3 2b ca 5f d3 e8 8b 4c 96 44 03 c1 8b 8e 88 00 00 00 5e 5b 8b 04 81 59 c3} 
		// mov ecx, dword ptr [esi]; mov edi, dword ptr [ecx + 4]; add edi, edx; mov dword ptr [ecx + 4], edi; mov ebx, dword ptr [esi + edx*4]; mov ecx, 0x18; sub eax, ebx; sub ecx, edx; pop edi; shr eax, cl; mov ecx, dword ptr [esi + edx*4 + 0x44]; add eax, ecx; mov ecx, dword ptr [esi + 0x88]; pop esi; pop ebx; mov eax, dword ptr [ecx + eax*4]; pop ecx; ret ;  
		$rule6 = {8b 08 8a 11 41 88 54 24 0c 89 08 8b 48 08 8b 54 24 0c c1 e1 08 81 e2 ff 00 00 00 0b ca 8b 50 04 83 c2 f8 89 48 08 8b ca 89 50 04 83 f9 08 73} 
		// mov ecx, dword ptr [eax]; mov dl, byte ptr [ecx]; inc ecx; mov byte ptr [esp + 0xc], dl; mov dword ptr [eax], ecx; mov ecx, dword ptr [eax + 8]; mov edx, dword ptr [esp + 0xc]; shl ecx, 8; and edx, 0xff; or ecx, edx; mov edx, dword ptr [eax + 4]; add edx, -8; mov dword ptr [eax + 8], ecx; mov ecx, edx; mov dword ptr [eax + 4], edx; cmp ecx, 8; jae 0x41b9ca;  
		$rule7 = {8b 96 8c 00 00 00 8b c8 c1 e9 10 33 db 8a 1c 11 8b d3 eb} 
		// mov edx, dword ptr [esi + 0x8c]; mov ecx, eax; shr ecx, 0x10; xor ebx, ebx; mov bl, byte ptr [ecx + edx]; mov edx, ebx; jmp 0x41ba64;  
		$rule8 = {8b 0e 88 01 8b 0e 41 47 89 0e 89 7c 24 10 e9} 
		// mov ecx, dword ptr [esi]; mov byte ptr [ecx], al; mov ecx, dword ptr [esi]; inc ecx; inc edi; mov dword ptr [esi], ecx; mov dword ptr [esp + 0x10], edi; jmp 0x41bf7c;  
		$rule9 = {5e 81 ee 6b ca 46 00 c3} 
		// pop esi; sub esi, 0x46ca6b; ret ;  
		$rule10 = {05 00 ff ff ff 8b e8 83 e0 07 c1 ed 03 8d 50 02 83 f8 07 89 54 24 14 0f85} 
		// add eax, 0xffffff00; mov ebp, eax; and eax, 7; shr ebp, 3; lea edx, [eax + 2]; cmp eax, 7; mov dword ptr [esp + 0x14], edx; jne 0x41be0f;  
		$rule11 = {8a 94 35 de c4 46 00 5e 84 c0 8b fa 74} 
		// mov dl, byte ptr [ebp + esi + 0x46c4de]; pop esi; test al, al; mov edi, edx; je 0x41bea8;  
		$rule12 = {8b 44 24 10 03 c7 89 44 24 10 8b f8 eb} 
		// mov eax, dword ptr [esp + 0x10]; add eax, edi; mov dword ptr [esp + 0x10], eax; mov edi, eax; jmp 0x41bf7c;  
		$rule13 = {3b 46 28 1b d2 83 c2 0a eb} 
		// cmp eax, dword ptr [esi + 0x28]; sbb edx, edx; add edx, 0xa; jmp 0x41ba64;  
		$rule14 = {8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcfe;  
		$rule15 = {8b 56 08 8b 46 0c b9 08 00 00 00 2b ca 03 d7 d3 e8 b9 18 00 00 00 89 56 08 2b cf 25 ff ff ff 00 d3 e8 03 d8 83 fb 03 73} 
		// mov edx, dword ptr [esi + 8]; mov eax, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edx; add edx, edi; shr eax, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edx; sub ecx, edi; and eax, 0xffffff; shr eax, cl; add ebx, eax; cmp ebx, 3; jae 0x41bf22;  
		$rule16 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 20 8b 4e 08 89 46 04 8b 44 24 20 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x20], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x20]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41beae;  
		$rule17 = {8b 86 54 02 00 00 8b 96 50 02 00 00 8d 4b fd 89 86 58 02 00 00 89 96 54 02 00 00 89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi + 0x254]; mov edx, dword ptr [esi + 0x250]; lea ecx, [ebx - 3]; mov dword ptr [esi + 0x258], eax; mov dword ptr [esi + 0x254], edx; mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf63;  
		$rule18 = {8b 8c 9e 50 02 00 00 85 db 74} 
		// mov ecx, dword ptr [esi + ebx*4 + 0x250]; test ebx, ebx; je 0x41bf43;  
		$rule19 = {8b 8b 60 02 00 00 8a 14 31 02 d0 80 e2 0f 88 54 34 24 46 eb} 
		// mov ecx, dword ptr [ebx + 0x260]; mov dl, byte ptr [ecx + esi]; add dl, al; and dl, 0xf; mov byte ptr [esp + esi + 0x24], dl; inc esi; jmp 0x41bc52;  
		$rule20 = {8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf63;  
		$rule21 = {c6 44 34 24 00 46 48 85 c0 7f} 
		// mov byte ptr [esp + esi + 0x24], 0; inc esi; dec eax; test eax, eax; jg 0x41bc3f;  
		$rule22 = {8b 46 08 8d 6f fd 83 f8 08 72} 
		// mov eax, dword ptr [esi + 8]; lea ebp, [edi - 3]; cmp eax, 8; jb 0x41be73;  
		$rule23 = {8b 46 08 8b 7e 0c b9 08 00 00 00 2b c8 03 c5 d3 ef b9 18 00 00 00 89 46 08 2b cd 81 e7 ff ff ff 00 d3 ef 8d 8e 30 01 00 00 e8} 
		// mov eax, dword ptr [esi + 8]; mov edi, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, eax; add eax, ebp; shr edi, cl; mov ecx, 0x18; mov dword ptr [esi + 8], eax; sub ecx, ebp; and edi, 0xffffff; shr edi, cl; lea ecx, [esi + 0x130]; call 0x41b9bc;  
		$rule24 = {03 c3 8d 1c f8 eb} 
		// add eax, ebx; lea ebx, [eax + edi*8]; jmp 0x41bf03;  
		$rule25 = {24 00 c1 c0 18 2b c3 89 06 83 c3 05 83 c6 04 83 e9 05 eb} 
		// and al, 0; rol eax, 0x18; sub eax, ebx; mov dword ptr [esi], eax; add ebx, 5; add esi, 4; sub ecx, 5; jmp 0x41b12b;  
		$rule26 = {8b 46 04 8b 56 0c c1 e2 08 8a 08 40 88 4c 24 1c 8b 4e 08 89 46 04 8b 44 24 1c 25 ff 00 00 00 83 c1 f8 0b d0 8b c1 83 f8 08 89 56 0c 89 4e 08 73} 
		// mov eax, dword ptr [esi + 4]; mov edx, dword ptr [esi + 0xc]; shl edx, 8; mov cl, byte ptr [eax]; inc eax; mov byte ptr [esp + 0x1c], cl; mov ecx, dword ptr [esi + 8]; mov dword ptr [esi + 4], eax; mov eax, dword ptr [esp + 0x1c]; and eax, 0xff; add ecx, -8; or edx, eax; mov eax, ecx; cmp eax, 8; mov dword ptr [esi + 0xc], edx; mov dword ptr [esi + 8], ecx; jae 0x41be42;  
		$rule27 = {8b 4e 08 33 db 56 e8} 
		// mov ecx, dword ptr [esi + 8]; xor ebx, ebx; push esi; call 0x41bcfe;  
		$rule28 = {8a 9c 30 c2 c4 46 00 5e 83 f9 08 72} 
		// mov bl, byte ptr [eax + esi + 0x46c4c2]; pop esi; cmp ecx, 8; jb 0x41bdd0;  
		$rule29 = {8b 7e 08 8b 56 0c b9 08 00 00 00 2b cf 03 fb d3 ea b9 18 00 00 00 89 7e 08 2b cb 81 e2 ff ff ff 00 d3 ea 33 c9 56 e8} 
		// mov edi, dword ptr [esi + 8]; mov edx, dword ptr [esi + 0xc]; mov ecx, 8; sub ecx, edi; add edi, ebx; shr edx, cl; mov ecx, 0x18; mov dword ptr [esi + 8], edi; sub ecx, ebx; and edx, 0xffffff; shr edx, cl; xor ecx, ecx; push esi; call 0x41bcfe;  
		$rule30 = {8a 8c 30 a6 c4 46 00 5e 8b 44 24 14 03 ca 03 c1 89 44 24 14 8a 86 64 02 00 00 8b 9c ae 68 02 00 00 33 d2 56 e8} 
		// mov cl, byte ptr [eax + esi + 0x46c4a6]; pop esi; mov eax, dword ptr [esp + 0x14]; add ecx, edx; add eax, ecx; mov dword ptr [esp + 0x14], eax; mov al, byte ptr [esi + 0x264]; mov ebx, dword ptr [esi + ebp*4 + 0x268]; xor edx, edx; push esi; call 0x41bcfe;  
		$rule31 = {8b 96 50 02 00 00 89 94 9e 50 02 00 00 eb} 
		// mov edx, dword ptr [esi + 0x250]; mov dword ptr [esi + ebx*4 + 0x250], edx; jmp 0x41bf3d;  
		$rule32 = {89 8e 50 02 00 00 8b 06 8b 7c 24 14 41 8d 14 38 3b c2 89 16 73} 
		// mov dword ptr [esi + 0x250], ecx; mov eax, dword ptr [esi]; mov edi, dword ptr [esp + 0x14]; inc ecx; lea edx, [eax + edi]; cmp eax, edx; mov dword ptr [esi], edx; jae 0x41bf63;  
		
	condition:
		pe.is_32bit() and (23 of them) and (pe.overlay.offset == 0 or for 16 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Upx
rule packer_Upx_v125_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v125"
		configs="nrv2b_1 nrv2b_best nrb2b_9"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d04a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cf99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d02c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cfab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cfd0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cfe8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d042;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cfdb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cff8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d01d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 89 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov eax, ebx; loop 0x41d04f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cf88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v125_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v125"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d0ae;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cfe9;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41d00c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d090;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41d018;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cffb;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41d034;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41d04c;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d0a6;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41d03f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d090;  
		$rule11 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d081;  
		$rule12 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41d05c;  
		$rule13 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d090;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 89 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov eax, ebx; loop 0x41d0b3;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cfd8;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41d00c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41cff0;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41d070;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v396_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v396"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c0ea;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c039;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c040;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c0cc;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c04b;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c070;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41c088;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c0e2;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41c07b;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c0cc;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c098;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c0cc;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c0bd;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c0ef;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c028;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c040;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v396_lzma_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v396"
		configs="lzma_1 lzma_9 lzma_best"
	strings:
		$rule0 = {8d 14 36 8b 6c 24 14 01 d5 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; add ebp, edx; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41cf6d;  
		$rule1 = {8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf9b;  
		$rule2 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 8d 04 01 66 89 45 00 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; lea eax, [ecx + eax]; mov word ptr [ebp], ax; jmp 0x41cf3a;  
		$rule3 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 66 89 4d 00 eb} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; mov word ptr [ebp], cx; jmp 0x41cf3a;  
		$rule4 = {8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6fb;  
		$rule5 = {8b ac 24 a4 00 00 00 39 6c 24 74 72} 
		// mov ebp, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], ebp; jb 0x41d6db;  
		$rule6 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d773;  
		$rule7 = {8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d553;  
		$rule8 = {8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d527;  
		$rule9 = {8b 74 24 74 23 74 24 6c 8b 44 24 60 8b 54 24 78 c1 e0 04 89 74 24 44 01 f0 81 7c 24 48 ff ff ff 00 8d 2c 42 77} 
		// mov esi, dword ptr [esp + 0x74]; and esi, dword ptr [esp + 0x6c]; mov eax, dword ptr [esp + 0x60]; mov edx, dword ptr [esp + 0x78]; shl eax, 4; mov dword ptr [esp + 0x44], esi; add eax, esi; cmp dword ptr [esp + 0x48], 0xffffff; lea ebp, [edx + eax*2]; ja 0x41ce05;  
		$rule10 = {8b 84 24 a4 00 00 00 39 44 24 74 0f82} 
		// mov eax, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], eax; jb 0x41cdc7;  
		$rule11 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 ca 0f af c1 39 c7 0f83} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41cffb;  
		$rule12 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 66 89 06 89 e8 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov word ptr [esi], ax; mov eax, ebp; jmp 0x41d568;  
		$rule13 = {8b 6c 24 24 4d 89 6c 24 24 75} 
		// mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4fc;  
		$rule14 = {d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d5ee;  
		$rule15 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 f2 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx esi, dx; imul eax, esi; cmp edi, eax; jae 0x41d677;  
		$rule16 = {8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf0c;  
		$rule17 = {8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d460;  
		$rule18 = {8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d647;  
		$rule19 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 89 ea 66 89 06 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov edx, ebp; mov word ptr [esi], ax; jmp 0x41d4a1;  
		$rule20 = {8b 74 24 28 4e 89 74 24 28 75} 
		// mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d435;  
		$rule21 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8d 45 01 66 89 16 8b 6c 24 24 4d 89 6c 24 24 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; lea eax, [ebp + 1]; mov word ptr [esi], dx; mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4fc;  
		$rule22 = {89 44 24 48 b8 00 08 00 00 29 c8 8a 4c 24 64 c1 f8 05 be 01 00 00 00 8d 04 02 0f b6 54 24 73 66 89 45 00 8b 44 24 74 23 44 24 68 8b 6c 24 78 d3 e0 b9 08 00 00 00 2b 4c 24 64 d3 fa 01 d0 69 c0 00 06 00 00 83 7c 24 60 06 8d 84 05 6c 0e 00 00 89 44 24 14 0f8e} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; mov cl, byte ptr [esp + 0x64]; sar eax, 5; mov esi, 1; lea eax, [edx + eax]; movzx edx, byte ptr [esp + 0x73]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x74]; and eax, dword ptr [esp + 0x68]; mov ebp, dword ptr [esp + 0x78]; shl eax, cl; mov ecx, 8; sub ecx, dword ptr [esp + 0x64]; sar edx, cl; add eax, edx; imul eax, eax, 0x600; cmp dword ptr [esp + 0x60], 6; lea eax, [ebp + eax + 0xe6c]; mov dword ptr [esp + 0x14], eax; jle 0x41cf42;  
		$rule23 = {8b 54 24 74 89 f0 8b 8c 24 a0 00 00 00 88 44 24 73 88 04 0a 42 83 7c 24 60 03 89 54 24 74 7f} 
		// mov edx, dword ptr [esp + 0x74]; mov eax, esi; mov ecx, dword ptr [esp + 0xa0]; mov byte ptr [esp + 0x73], al; mov byte ptr [edx + ecx], al; inc edx; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0x74], edx; jg 0x41cfe0;  
		$rule24 = {d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ced1;  
		$rule25 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf9b;  
		$rule26 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8b 44 24 18 66 89 55 00 8b 54 24 1c 40 09 14 24 8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov eax, dword ptr [esp + 0x18]; mov word ptr [ebp], dx; mov edx, dword ptr [esp + 0x1c]; inc eax; or dword ptr [esp], edx; mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d619;  
		$rule27 = {2b 7c 24 48 83 ce 01 4a 75} 
		// sub edi, dword ptr [esp + 0x48]; or esi, 1; dec edx; jne 0x41d5b9;  
		$rule28 = {89 44 24 48 b8 00 08 00 00 29 f0 c1 f8 05 8d 04 02 66 89 45 00 8b 44 24 18 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; sar eax, 5; lea eax, [edx + eax]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x18]; jmp 0x41d696;  
		$rule29 = {8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d619;  
		$rule30 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 83 7c 24 3c 00 8d 04 01 66 89 85 00 02 00 00 74} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; cmp dword ptr [esp + 0x3c], 0; lea eax, [ecx + eax]; mov word ptr [ebp + 0x200], ax; je 0x41cf2c;  
		$rule31 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 16 8d 55 01 8b 74 24 28 4e 89 74 24 28 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [esi], dx; lea edx, [ebp + 1]; mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d435;  
		$rule32 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 83 7c 24 3c 00 66 89 8d 00 02 00 00 74} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; cmp dword ptr [esp + 0x3c], 0; mov word ptr [ebp + 0x200], cx; je 0x41cf3a;  
		$rule33 = {8b 4c 24 48 29 c7 8b 74 24 60 29 c1 89 d0 66 c1 e8 05 66 29 c2 81 f9 ff ff ff 00 66 89 55 00 8b 6c 24 78 8d 74 75 00 89 74 24 38 77} 
		// mov ecx, dword ptr [esp + 0x48]; sub edi, eax; mov esi, dword ptr [esp + 0x60]; sub ecx, eax; mov eax, edx; shr ax, 5; sub dx, ax; cmp ecx, 0xffffff; mov word ptr [ebp], dx; mov ebp, dword ptr [esp + 0x78]; lea esi, [ebp + esi*2]; mov dword ptr [esp + 0x38], esi; ja 0x41d03e;  
		$rule34 = {8a 4c 24 30 b8 01 00 00 00 d3 e0 29 c2 03 54 24 2c 83 7c 24 60 03 89 54 24 0c 0f8f} 
		// mov cl, byte ptr [esp + 0x30]; mov eax, 1; shl eax, cl; sub edx, eax; add edx, dword ptr [esp + 0x2c]; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0xc], edx; jg 0x41d6b3;  
		$rule35 = {8b 4c 24 0c 8b 6c 24 74 83 c1 02 39 6c 24 5c 77} 
		// mov ecx, dword ptr [esp + 0xc]; mov ebp, dword ptr [esp + 0x74]; add ecx, 2; cmp dword ptr [esp + 0x5c], ebp; ja 0x41d723;  
		$rule36 = {8b 84 24 a0 00 00 00 89 ea 2b 44 24 5c 03 94 24 a0 00 00 00 8d 34 28 8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov eax, dword ptr [esp + 0xa0]; mov edx, ebp; sub eax, dword ptr [esp + 0x5c]; add edx, dword ptr [esp + 0xa0]; lea esi, [eax + ebp]; mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6fb;  
		$rule37 = {8b 4c 24 30 ba 01 00 00 00 89 4c 24 28 8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov ecx, dword ptr [esp + 0x30]; mov edx, 1; mov dword ptr [esp + 0x28], ecx; lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d460;  
		$rule38 = {66 8b 11 89 f0 c1 e8 0b 0f b7 ea 0f af c5 39 c7 73} 
		// mov dx, word ptr [ecx]; mov eax, esi; shr eax, 0xb; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d37d;  
		$rule39 = {89 44 24 48 b8 00 08 00 00 29 e8 c1 64 24 44 04 c1 f8 05 c7 44 24 2c 00 00 00 00 8d 04 02 66 89 01 8b 44 24 44 8d 4c 01 04 89 4c 24 10 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ebp; shl dword ptr [esp + 0x44], 4; sar eax, 5; mov dword ptr [esp + 0x2c], 0; lea eax, [edx + eax]; mov word ptr [ecx], ax; mov eax, dword ptr [esp + 0x44]; lea ecx, [ecx + eax + 4]; mov dword ptr [esp + 0x10], ecx; jmp 0x41d3ef;  
		$rule40 = {8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d0aa;  
		$rule41 = {89 c6 b8 00 08 00 00 29 e8 8b 6c 24 58 c1 f8 05 8b 4c 24 54 8d 04 02 8b 54 24 38 89 4c 24 50 8b 4c 24 78 66 89 82 80 01 00 00 8b 44 24 5c 89 6c 24 54 89 44 24 58 31 c0 83 7c 24 60 06 0f 9f c0 81 c1 64 06 00 00 8d 04 40 89 44 24 60 e9} 
		// mov esi, eax; mov eax, 0x800; sub eax, ebp; mov ebp, dword ptr [esp + 0x58]; sar eax, 5; mov ecx, dword ptr [esp + 0x54]; lea eax, [edx + eax]; mov edx, dword ptr [esp + 0x38]; mov dword ptr [esp + 0x50], ecx; mov ecx, dword ptr [esp + 0x78]; mov word ptr [edx + 0x180], ax; mov eax, dword ptr [esp + 0x5c]; mov dword ptr [esp + 0x54], ebp; mov dword ptr [esp + 0x58], eax; xor eax, eax; cmp dword ptr [esp + 0x60], 6; setg al; add ecx, 0x664; lea eax, [eax + eax*2]; mov dword ptr [esp + 0x60], eax; jmp 0x41d31e;  
		$rule42 = {83 44 24 60 07 83 fa 03 89 d0 7e} 
		// add dword ptr [esp + 0x60], 7; cmp edx, 3; mov eax, edx; jle 0x41d4dd;  
		$rule43 = {8d 50 c0 83 fa 03 89 14 24 0f8e} 
		// lea edx, [eax - 0x40]; cmp edx, 3; mov dword ptr [esp], edx; jle 0x41d6a9;  
		$rule44 = {8b 34 24 46 89 74 24 5c 74} 
		// mov esi, dword ptr [esp]; inc esi; mov dword ptr [esp + 0x5c], esi; je 0x41d70c;  
		$rule45 = {89 d0 89 d6 d1 f8 83 e6 01 8d 48 ff 83 ce 02 83 fa 0d 89 4c 24 20 7f} 
		// mov eax, edx; mov esi, edx; sar eax, 1; and esi, 1; lea ecx, [eax - 1]; or esi, 2; cmp edx, 0xd; mov dword ptr [esp + 0x20], ecx; jg 0x41d5b6;  
		$rule46 = {8b 44 24 74 2b 44 24 5c 8b 94 24 a0 00 00 00 0f b6 04 02 89 44 24 40 d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// mov eax, dword ptr [esp + 0x74]; sub eax, dword ptr [esp + 0x5c]; mov edx, dword ptr [esp + 0xa0]; movzx eax, byte ptr [edx + eax]; mov dword ptr [esp + 0x40], eax; shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ced1;  
		$rule47 = {66 c7 00 00 04 83 c0 02 } 
		// mov word ptr [eax], 0x400; add eax, 2; loop 0x41cd73;  
		$rule48 = {8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d527;  
		$rule49 = {8d 50 fb 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [eax - 5]; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5db;  
		$rule50 = {8b 44 24 78 c1 e6 04 89 34 24 05 44 06 00 00 c7 44 24 20 04 00 00 00 89 44 24 04 c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, dword ptr [esp + 0x78]; shl esi, 4; mov dword ptr [esp], esi; add eax, 0x644; mov dword ptr [esp + 0x20], 4; mov dword ptr [esp + 4], eax; mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d647;  
		$rule51 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d553;  
		$rule52 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d5ee;  
		$rule53 = {50 39 cc 75} 
		// push eax; cmp esp, ecx; jne 0x41d762;  
		$rule54 = {50 39 dc 75} 
		// push eax; cmp esp, ebx; jne 0x41cca8;  
		$rule55 = {89 ce 29 c7 29 c6 89 d0 66 c1 e8 05 8b 4c 24 38 66 29 c2 81 fe ff ff ff 00 66 89 91 80 01 00 00 77} 
		// mov esi, ecx; sub edi, eax; sub esi, eax; mov eax, edx; shr ax, 5; mov ecx, dword ptr [esp + 0x38]; sub dx, ax; cmp esi, 0xffffff; mov word ptr [ecx + 0x180], dx; ja 0x41d0e2;  
		$rule56 = {8b 6c 24 78 d3 e6 01 d2 89 34 24 8d 44 75 00 29 d0 05 5e 05 00 00 89 44 24 04 eb} 
		// mov ebp, dword ptr [esp + 0x78]; shl esi, cl; add edx, edx; mov dword ptr [esp], esi; lea eax, [ebp + esi*2]; sub eax, edx; add eax, 0x55e; mov dword ptr [esp + 4], eax; jmp 0x41d60c;  
		$rule57 = {c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d647;  
		$rule58 = {8b 6c 24 38 89 f2 c1 ea 0b 66 8b 8d 98 01 00 00 0f b7 c1 0f af d0 39 d7 0f83} 
		// mov ebp, dword ptr [esp + 0x38]; mov edx, esi; shr edx, 0xb; mov cx, word ptr [ebp + 0x198]; movzx eax, cx; imul edx, eax; cmp edi, edx; jae 0x41d1e3;  
		$rule59 = {b8 03 00 00 00 8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, 3; mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d527;  
		$rule60 = {bd 00 08 00 00 89 d6 29 c5 c7 44 24 34 00 08 00 00 89 e8 c1 f8 05 8d 04 01 8b 4c 24 38 66 89 81 98 01 00 00 8b 44 24 60 8b 4c 24 44 c1 e0 05 03 44 24 78 81 fa ff ff ff 00 8d 2c 48 77} 
		// mov ebp, 0x800; mov esi, edx; sub ebp, eax; mov dword ptr [esp + 0x34], 0x800; mov eax, ebp; sar eax, 5; lea eax, [ecx + eax]; mov ecx, dword ptr [esp + 0x38]; mov word ptr [ecx + 0x198], ax; mov eax, dword ptr [esp + 0x60]; mov ecx, dword ptr [esp + 0x44]; shl eax, 5; add eax, dword ptr [esp + 0x78]; cmp edx, 0xffffff; lea ebp, [eax + ecx*2]; ja 0x41d154;  
		$rule61 = {29 c6 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 95 e0 01 00 00 e9} 
		// sub esi, eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [ebp + 0x1e0], dx; jmp 0x41d302;  
		$rule62 = {31 c0 83 7c 24 60 06 8b 4c 24 78 0f 9f c0 81 c1 68 0a 00 00 8d 44 40 08 89 44 24 60 81 fe ff ff ff 00 77} 
		// xor eax, eax; cmp dword ptr [esp + 0x60], 6; mov ecx, dword ptr [esp + 0x78]; setg al; add ecx, 0xa68; lea eax, [eax + eax*2 + 8]; mov dword ptr [esp + 0x60], eax; cmp esi, 0xffffff; ja 0x41d33c;  
		$rule63 = {66 8b 95 e0 01 00 00 89 f0 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov dx, word ptr [ebp + 0x1e0]; mov eax, esi; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d1ca;  
		$rule64 = {0f b6 03 c1 e7 08 c1 e1 08 43 09 c7 8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// movzx eax, byte ptr [ebx]; shl edi, 8; shl ecx, 8; inc ebx; or edi, eax; mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d0aa;  
		
	condition:
		pe.is_32bit() and (45 of them) and (pe.overlay.offset == 0 or for 31 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v396_nrv2e_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v396"
		config="nrv2e_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41ceb2;  
		$rule1 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41ce04;  
		$rule2 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cde1;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41ce94;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cdf3;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41ce3b;  
		$rule6 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41ceaa;  
		$rule7 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41ce46;  
		$rule8 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41ce10;  
		$rule9 = {81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41ce94;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41ce54;  
		$rule11 = {11 c9 01 db 73} 
		// adc ecx, ecx; add ebx, ebx; jae 0x41ce56;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41ce94;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41ceb7;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cdd0;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41ce04;  
		$rule16 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41ce86;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c9 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jmp 0x41ce75;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v396_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v396"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c2ae;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c1e9;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c20c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c290;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41c218;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c1fb;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c234;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41c24c;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c2a6;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41c23f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c290;  
		$rule11 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c25c;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c290;  
		$rule13 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c281;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c2b3;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c1d8;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c20c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41c1f0;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41c270;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v200_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v200"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d04a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cf99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d02c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cfab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cfd0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cfe8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d042;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cfdb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cff8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d01d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41d04f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cf88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v200_nrv2e_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v200"
		config="nrv2e_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c61a;  
		$rule1 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c56c;  
		$rule2 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c5fc;  
		$rule3 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c549;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41c578;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c55b;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c5a3;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c612;  
		$rule8 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41c5ae;  
		$rule9 = {81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c5fc;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c5bc;  
		$rule11 = {11 c9 01 db 73} 
		// adc ecx, ecx; add ebx, ebx; jae 0x41c5be;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c5ee;  
		$rule13 = {83 c1 02 81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c5fc;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c61f;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c538;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c56c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41c550;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v200_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v200"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c20e;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c149;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c1f0;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41c178;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c15b;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c194;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41c1ac;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c206;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41c19f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule11 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c1bc;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule13 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c1e1;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c213;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c138;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41c150;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41c1d0;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v100_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v100"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d04a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cf99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d02c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cfab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cfd0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cfe8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d042;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cfdb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cff8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d01d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 89 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov eax, ebx; loop 0x41d04f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cf88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v100_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v100"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d0ae;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cfe9;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41d00c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d090;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41d018;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cffb;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41d034;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41d04c;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d0a6;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41d03f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d090;  
		$rule11 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d081;  
		$rule12 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41d05c;  
		$rule13 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d090;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 89 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov eax, ebx; loop 0x41d0b3;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cfd8;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41d00c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41cff0;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41d070;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v120_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v120"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d04a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cf99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d02c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cfab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cfd0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cfe8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d042;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cfdb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cff8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d01d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41d04f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cf88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v120_lzma_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v120"
		configs="lzma_1 lzma_9 lzma_best"
	strings:
		$rule0 = {8d 14 36 8b 6c 24 14 01 d5 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; add ebp, edx; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41cf12;  
		$rule1 = {8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf40;  
		$rule2 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 8d 04 01 66 89 45 00 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; lea eax, [ecx + eax]; mov word ptr [ebp], ax; jmp 0x41cedf;  
		$rule3 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 66 89 4d 00 eb} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; mov word ptr [ebp], cx; jmp 0x41cedf;  
		$rule4 = {8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6a0;  
		$rule5 = {8b ac 24 a4 00 00 00 39 6c 24 74 72} 
		// mov ebp, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], ebp; jb 0x41d680;  
		$rule6 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d718;  
		$rule7 = {8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d4f8;  
		$rule8 = {8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule9 = {8b 74 24 74 23 74 24 6c 8b 44 24 60 8b 54 24 78 c1 e0 04 89 74 24 44 01 f0 81 7c 24 48 ff ff ff 00 8d 2c 42 77} 
		// mov esi, dword ptr [esp + 0x74]; and esi, dword ptr [esp + 0x6c]; mov eax, dword ptr [esp + 0x60]; mov edx, dword ptr [esp + 0x78]; shl eax, 4; mov dword ptr [esp + 0x44], esi; add eax, esi; cmp dword ptr [esp + 0x48], 0xffffff; lea ebp, [edx + eax*2]; ja 0x41cdaa;  
		$rule10 = {8b 84 24 a4 00 00 00 39 44 24 74 0f82} 
		// mov eax, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], eax; jb 0x41cd6c;  
		$rule11 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 ca 0f af c1 39 c7 0f83} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41cfa0;  
		$rule12 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 66 89 06 89 e8 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov word ptr [esi], ax; mov eax, ebp; jmp 0x41d50d;  
		$rule13 = {8b 6c 24 24 4d 89 6c 24 24 75} 
		// mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4a1;  
		$rule14 = {d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d593;  
		$rule15 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 f2 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx esi, dx; imul eax, esi; cmp edi, eax; jae 0x41d61c;  
		$rule16 = {8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41ceb1;  
		$rule17 = {8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d405;  
		$rule18 = {8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule19 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 89 ea 66 89 06 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov edx, ebp; mov word ptr [esi], ax; jmp 0x41d446;  
		$rule20 = {8b 74 24 28 4e 89 74 24 28 75} 
		// mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d3da;  
		$rule21 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8d 45 01 66 89 16 8b 6c 24 24 4d 89 6c 24 24 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; lea eax, [ebp + 1]; mov word ptr [esi], dx; mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4a1;  
		$rule22 = {89 44 24 48 b8 00 08 00 00 29 c8 8a 4c 24 64 c1 f8 05 be 01 00 00 00 8d 04 02 0f b6 54 24 73 66 89 45 00 8b 44 24 74 23 44 24 68 8b 6c 24 78 d3 e0 b9 08 00 00 00 2b 4c 24 64 d3 fa 01 d0 69 c0 00 06 00 00 83 7c 24 60 06 8d 84 05 6c 0e 00 00 89 44 24 14 0f8e} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; mov cl, byte ptr [esp + 0x64]; sar eax, 5; mov esi, 1; lea eax, [edx + eax]; movzx edx, byte ptr [esp + 0x73]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x74]; and eax, dword ptr [esp + 0x68]; mov ebp, dword ptr [esp + 0x78]; shl eax, cl; mov ecx, 8; sub ecx, dword ptr [esp + 0x64]; sar edx, cl; add eax, edx; imul eax, eax, 0x600; cmp dword ptr [esp + 0x60], 6; lea eax, [ebp + eax + 0xe6c]; mov dword ptr [esp + 0x14], eax; jle 0x41cee7;  
		$rule23 = {8b 54 24 74 89 f0 8b 8c 24 a0 00 00 00 88 44 24 73 88 04 0a 42 83 7c 24 60 03 89 54 24 74 7f} 
		// mov edx, dword ptr [esp + 0x74]; mov eax, esi; mov ecx, dword ptr [esp + 0xa0]; mov byte ptr [esp + 0x73], al; mov byte ptr [edx + ecx], al; inc edx; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0x74], edx; jg 0x41cf85;  
		$rule24 = {d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ce76;  
		$rule25 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf40;  
		$rule26 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8b 44 24 18 66 89 55 00 8b 54 24 1c 40 09 14 24 8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov eax, dword ptr [esp + 0x18]; mov word ptr [ebp], dx; mov edx, dword ptr [esp + 0x1c]; inc eax; or dword ptr [esp], edx; mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d5be;  
		$rule27 = {2b 7c 24 48 83 ce 01 4a 75} 
		// sub edi, dword ptr [esp + 0x48]; or esi, 1; dec edx; jne 0x41d55e;  
		$rule28 = {89 44 24 48 b8 00 08 00 00 29 f0 c1 f8 05 8d 04 02 66 89 45 00 8b 44 24 18 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; sar eax, 5; lea eax, [edx + eax]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x18]; jmp 0x41d63b;  
		$rule29 = {8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d5be;  
		$rule30 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 83 7c 24 3c 00 8d 04 01 66 89 85 00 02 00 00 74} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; cmp dword ptr [esp + 0x3c], 0; lea eax, [ecx + eax]; mov word ptr [ebp + 0x200], ax; je 0x41ced1;  
		$rule31 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 16 8d 55 01 8b 74 24 28 4e 89 74 24 28 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [esi], dx; lea edx, [ebp + 1]; mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d3da;  
		$rule32 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 83 7c 24 3c 00 66 89 8d 00 02 00 00 74} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; cmp dword ptr [esp + 0x3c], 0; mov word ptr [ebp + 0x200], cx; je 0x41cedf;  
		$rule33 = {8b 4c 24 48 29 c7 8b 74 24 60 29 c1 89 d0 66 c1 e8 05 66 29 c2 81 f9 ff ff ff 00 66 89 55 00 8b 6c 24 78 8d 74 75 00 89 74 24 38 77} 
		// mov ecx, dword ptr [esp + 0x48]; sub edi, eax; mov esi, dword ptr [esp + 0x60]; sub ecx, eax; mov eax, edx; shr ax, 5; sub dx, ax; cmp ecx, 0xffffff; mov word ptr [ebp], dx; mov ebp, dword ptr [esp + 0x78]; lea esi, [ebp + esi*2]; mov dword ptr [esp + 0x38], esi; ja 0x41cfe3;  
		$rule34 = {8a 4c 24 30 b8 01 00 00 00 d3 e0 29 c2 03 54 24 2c 83 7c 24 60 03 89 54 24 0c 0f8f} 
		// mov cl, byte ptr [esp + 0x30]; mov eax, 1; shl eax, cl; sub edx, eax; add edx, dword ptr [esp + 0x2c]; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0xc], edx; jg 0x41d658;  
		$rule35 = {8b 4c 24 0c 8b 6c 24 74 83 c1 02 39 6c 24 5c 77} 
		// mov ecx, dword ptr [esp + 0xc]; mov ebp, dword ptr [esp + 0x74]; add ecx, 2; cmp dword ptr [esp + 0x5c], ebp; ja 0x41d6c8;  
		$rule36 = {8b 84 24 a0 00 00 00 89 ea 2b 44 24 5c 03 94 24 a0 00 00 00 8d 34 28 8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov eax, dword ptr [esp + 0xa0]; mov edx, ebp; sub eax, dword ptr [esp + 0x5c]; add edx, dword ptr [esp + 0xa0]; lea esi, [eax + ebp]; mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6a0;  
		$rule37 = {8b 4c 24 30 ba 01 00 00 00 89 4c 24 28 8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov ecx, dword ptr [esp + 0x30]; mov edx, 1; mov dword ptr [esp + 0x28], ecx; lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d405;  
		$rule38 = {66 8b 11 89 f0 c1 e8 0b 0f b7 ea 0f af c5 39 c7 73} 
		// mov dx, word ptr [ecx]; mov eax, esi; shr eax, 0xb; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d322;  
		$rule39 = {89 44 24 48 b8 00 08 00 00 29 e8 c1 64 24 44 04 c1 f8 05 c7 44 24 2c 00 00 00 00 8d 04 02 66 89 01 8b 44 24 44 8d 4c 01 04 89 4c 24 10 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ebp; shl dword ptr [esp + 0x44], 4; sar eax, 5; mov dword ptr [esp + 0x2c], 0; lea eax, [edx + eax]; mov word ptr [ecx], ax; mov eax, dword ptr [esp + 0x44]; lea ecx, [ecx + eax + 4]; mov dword ptr [esp + 0x10], ecx; jmp 0x41d394;  
		$rule40 = {8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d04f;  
		$rule41 = {89 c6 b8 00 08 00 00 29 e8 8b 6c 24 58 c1 f8 05 8b 4c 24 54 8d 04 02 8b 54 24 38 89 4c 24 50 8b 4c 24 78 66 89 82 80 01 00 00 8b 44 24 5c 89 6c 24 54 89 44 24 58 31 c0 83 7c 24 60 06 0f 9f c0 81 c1 64 06 00 00 8d 04 40 89 44 24 60 e9} 
		// mov esi, eax; mov eax, 0x800; sub eax, ebp; mov ebp, dword ptr [esp + 0x58]; sar eax, 5; mov ecx, dword ptr [esp + 0x54]; lea eax, [edx + eax]; mov edx, dword ptr [esp + 0x38]; mov dword ptr [esp + 0x50], ecx; mov ecx, dword ptr [esp + 0x78]; mov word ptr [edx + 0x180], ax; mov eax, dword ptr [esp + 0x5c]; mov dword ptr [esp + 0x54], ebp; mov dword ptr [esp + 0x58], eax; xor eax, eax; cmp dword ptr [esp + 0x60], 6; setg al; add ecx, 0x664; lea eax, [eax + eax*2]; mov dword ptr [esp + 0x60], eax; jmp 0x41d2c3;  
		$rule42 = {83 44 24 60 07 83 fa 03 89 d0 7e} 
		// add dword ptr [esp + 0x60], 7; cmp edx, 3; mov eax, edx; jle 0x41d482;  
		$rule43 = {8d 50 c0 83 fa 03 89 14 24 0f8e} 
		// lea edx, [eax - 0x40]; cmp edx, 3; mov dword ptr [esp], edx; jle 0x41d64e;  
		$rule44 = {8b 34 24 46 89 74 24 5c 74} 
		// mov esi, dword ptr [esp]; inc esi; mov dword ptr [esp + 0x5c], esi; je 0x41d6b1;  
		$rule45 = {89 d0 89 d6 d1 f8 83 e6 01 8d 48 ff 83 ce 02 83 fa 0d 89 4c 24 20 7f} 
		// mov eax, edx; mov esi, edx; sar eax, 1; and esi, 1; lea ecx, [eax - 1]; or esi, 2; cmp edx, 0xd; mov dword ptr [esp + 0x20], ecx; jg 0x41d55b;  
		$rule46 = {8b 44 24 74 2b 44 24 5c 8b 94 24 a0 00 00 00 0f b6 04 02 89 44 24 40 d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// mov eax, dword ptr [esp + 0x74]; sub eax, dword ptr [esp + 0x5c]; mov edx, dword ptr [esp + 0xa0]; movzx eax, byte ptr [edx + eax]; mov dword ptr [esp + 0x40], eax; shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ce76;  
		$rule47 = {66 c7 00 00 04 83 c0 02 } 
		// mov word ptr [eax], 0x400; add eax, 2; loop 0x41cd18;  
		$rule48 = {8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule49 = {8d 50 fb 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [eax - 5]; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d580;  
		$rule50 = {8b 44 24 78 c1 e6 04 89 34 24 05 44 06 00 00 c7 44 24 20 04 00 00 00 89 44 24 04 c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, dword ptr [esp + 0x78]; shl esi, 4; mov dword ptr [esp], esi; add eax, 0x644; mov dword ptr [esp + 0x20], 4; mov dword ptr [esp + 4], eax; mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule51 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d4f8;  
		$rule52 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d593;  
		$rule53 = {50 39 cc 75} 
		// push eax; cmp esp, ecx; jne 0x41d707;  
		$rule54 = {50 39 dc 75} 
		// push eax; cmp esp, ebx; jne 0x41cc48;  
		$rule55 = {89 ce 29 c7 29 c6 89 d0 66 c1 e8 05 8b 4c 24 38 66 29 c2 81 fe ff ff ff 00 66 89 91 80 01 00 00 77} 
		// mov esi, ecx; sub edi, eax; sub esi, eax; mov eax, edx; shr ax, 5; mov ecx, dword ptr [esp + 0x38]; sub dx, ax; cmp esi, 0xffffff; mov word ptr [ecx + 0x180], dx; ja 0x41d087;  
		$rule56 = {8b 6c 24 78 d3 e6 01 d2 89 34 24 8d 44 75 00 29 d0 05 5e 05 00 00 89 44 24 04 eb} 
		// mov ebp, dword ptr [esp + 0x78]; shl esi, cl; add edx, edx; mov dword ptr [esp], esi; lea eax, [ebp + esi*2]; sub eax, edx; add eax, 0x55e; mov dword ptr [esp + 4], eax; jmp 0x41d5b1;  
		$rule57 = {c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule58 = {8b 6c 24 38 89 f2 c1 ea 0b 66 8b 8d 98 01 00 00 0f b7 c1 0f af d0 39 d7 0f83} 
		// mov ebp, dword ptr [esp + 0x38]; mov edx, esi; shr edx, 0xb; mov cx, word ptr [ebp + 0x198]; movzx eax, cx; imul edx, eax; cmp edi, edx; jae 0x41d188;  
		$rule59 = {b8 03 00 00 00 8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, 3; mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule60 = {bd 00 08 00 00 89 d6 29 c5 c7 44 24 34 00 08 00 00 89 e8 c1 f8 05 8d 04 01 8b 4c 24 38 66 89 81 98 01 00 00 8b 44 24 60 8b 4c 24 44 c1 e0 05 03 44 24 78 81 fa ff ff ff 00 8d 2c 48 77} 
		// mov ebp, 0x800; mov esi, edx; sub ebp, eax; mov dword ptr [esp + 0x34], 0x800; mov eax, ebp; sar eax, 5; lea eax, [ecx + eax]; mov ecx, dword ptr [esp + 0x38]; mov word ptr [ecx + 0x198], ax; mov eax, dword ptr [esp + 0x60]; mov ecx, dword ptr [esp + 0x44]; shl eax, 5; add eax, dword ptr [esp + 0x78]; cmp edx, 0xffffff; lea ebp, [eax + ecx*2]; ja 0x41d0f9;  
		$rule61 = {29 c6 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 95 e0 01 00 00 e9} 
		// sub esi, eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [ebp + 0x1e0], dx; jmp 0x41d2a7;  
		$rule62 = {31 c0 83 7c 24 60 06 8b 4c 24 78 0f 9f c0 81 c1 68 0a 00 00 8d 44 40 08 89 44 24 60 81 fe ff ff ff 00 77} 
		// xor eax, eax; cmp dword ptr [esp + 0x60], 6; mov ecx, dword ptr [esp + 0x78]; setg al; add ecx, 0xa68; lea eax, [eax + eax*2 + 8]; mov dword ptr [esp + 0x60], eax; cmp esi, 0xffffff; ja 0x41d2e1;  
		$rule63 = {66 8b 95 e0 01 00 00 89 f0 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov dx, word ptr [ebp + 0x1e0]; mov eax, esi; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d16f;  
		$rule64 = {0f b6 03 c1 e7 08 c1 e1 08 43 09 c7 8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// movzx eax, byte ptr [ebx]; shl edi, 8; shl ecx, 8; inc ebx; or edi, eax; mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d04f;  
		$rule65 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41ceb1;  
		
	condition:
		pe.is_32bit() and (46 of them) and (pe.overlay.offset == 0 or for 32 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v120_nrv2e_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v120"
		config="nrv2e_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41cd92;  
		$rule1 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cce4;  
		$rule2 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41ccc1;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41cd74;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41ccd3;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cd1b;  
		$rule6 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41cd8a;  
		$rule7 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41cd26;  
		$rule8 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41ccf0;  
		$rule9 = {81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cd74;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cd34;  
		$rule11 = {11 c9 01 db 73} 
		// adc ecx, ecx; add ebx, ebx; jae 0x41cd36;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cd74;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41cd97;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41ccb0;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cce4;  
		$rule16 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41cd66;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41ccc8;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v120_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v120"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c20e;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c149;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c1f0;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41c178;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c15b;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c194;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41c1ac;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c206;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41c19f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule11 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c1bc;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule13 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c1e1;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c213;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c138;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41c150;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41c1d0;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v309_nrv2b_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v309"
		configs="nrv2b_1 nrv2b_9 nrv2b_best"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d04a;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41cf99;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41d02c;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41cfab;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cfd0;  
		$rule6 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41cfe8;  
		$rule7 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41d042;  
		$rule8 = {89 c5 01 db 75} 
		// mov ebp, eax; add ebx, ebx; jne 0x41cfdb;  
		$rule9 = {81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cff8;  
		$rule11 = {83 c1 02 81 fd 00 f3 ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffff300; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41d02c;  
		$rule12 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41d01d;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41d04f;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41cf88;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cfa0;  
		
	condition:
		pe.is_32bit() and (11 of them) and (pe.overlay.offset == 0 or for 7 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v309_lzma_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v309"
		configs="lzma_1 lzma_9 lzma_best"
	strings:
		$rule0 = {8d 14 36 8b 6c 24 14 01 d5 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; add ebp, edx; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41cf12;  
		$rule1 = {8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf40;  
		$rule2 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 8d 04 01 66 89 45 00 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; lea eax, [ecx + eax]; mov word ptr [ebp], ax; jmp 0x41cedf;  
		$rule3 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 66 89 4d 00 eb} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; mov word ptr [ebp], cx; jmp 0x41cedf;  
		$rule4 = {8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6a0;  
		$rule5 = {8b ac 24 a4 00 00 00 39 6c 24 74 72} 
		// mov ebp, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], ebp; jb 0x41d680;  
		$rule6 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41d718;  
		$rule7 = {8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d4f8;  
		$rule8 = {8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule9 = {8b 74 24 74 23 74 24 6c 8b 44 24 60 8b 54 24 78 c1 e0 04 89 74 24 44 01 f0 81 7c 24 48 ff ff ff 00 8d 2c 42 77} 
		// mov esi, dword ptr [esp + 0x74]; and esi, dword ptr [esp + 0x6c]; mov eax, dword ptr [esp + 0x60]; mov edx, dword ptr [esp + 0x78]; shl eax, 4; mov dword ptr [esp + 0x44], esi; add eax, esi; cmp dword ptr [esp + 0x48], 0xffffff; lea ebp, [edx + eax*2]; ja 0x41cdaa;  
		$rule10 = {8b 84 24 a4 00 00 00 39 44 24 74 0f82} 
		// mov eax, dword ptr [esp + 0xa4]; cmp dword ptr [esp + 0x74], eax; jb 0x41cd6c;  
		$rule11 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 ca 0f af c1 39 c7 0f83} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41cfa0;  
		$rule12 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 66 89 06 89 e8 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov word ptr [esi], ax; mov eax, ebp; jmp 0x41d50d;  
		$rule13 = {8b 6c 24 24 4d 89 6c 24 24 75} 
		// mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4a1;  
		$rule14 = {d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d593;  
		$rule15 = {8b 44 24 48 66 8b 55 00 c1 e8 0b 0f b7 f2 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [ebp]; shr eax, 0xb; movzx esi, dx; imul eax, esi; cmp edi, eax; jae 0x41d61c;  
		$rule16 = {8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41ceb1;  
		$rule17 = {8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d405;  
		$rule18 = {8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule19 = {89 44 24 48 b8 00 08 00 00 29 c8 c1 f8 05 8d 04 02 89 ea 66 89 06 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; sar eax, 5; lea eax, [edx + eax]; mov edx, ebp; mov word ptr [esi], ax; jmp 0x41d446;  
		$rule20 = {8b 74 24 28 4e 89 74 24 28 75} 
		// mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d3da;  
		$rule21 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8d 45 01 66 89 16 8b 6c 24 24 4d 89 6c 24 24 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; lea eax, [ebp + 1]; mov word ptr [esi], dx; mov ebp, dword ptr [esp + 0x24]; dec ebp; mov dword ptr [esp + 0x24], ebp; jne 0x41d4a1;  
		$rule22 = {89 44 24 48 b8 00 08 00 00 29 c8 8a 4c 24 64 c1 f8 05 be 01 00 00 00 8d 04 02 0f b6 54 24 73 66 89 45 00 8b 44 24 74 23 44 24 68 8b 6c 24 78 d3 e0 b9 08 00 00 00 2b 4c 24 64 d3 fa 01 d0 69 c0 00 06 00 00 83 7c 24 60 06 8d 84 05 6c 0e 00 00 89 44 24 14 0f8e} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ecx; mov cl, byte ptr [esp + 0x64]; sar eax, 5; mov esi, 1; lea eax, [edx + eax]; movzx edx, byte ptr [esp + 0x73]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x74]; and eax, dword ptr [esp + 0x68]; mov ebp, dword ptr [esp + 0x78]; shl eax, cl; mov ecx, 8; sub ecx, dword ptr [esp + 0x64]; sar edx, cl; add eax, edx; imul eax, eax, 0x600; cmp dword ptr [esp + 0x60], 6; lea eax, [ebp + eax + 0xe6c]; mov dword ptr [esp + 0x14], eax; jle 0x41cee7;  
		$rule23 = {8b 54 24 74 89 f0 8b 8c 24 a0 00 00 00 88 44 24 73 88 04 0a 42 83 7c 24 60 03 89 54 24 74 7f} 
		// mov edx, dword ptr [esp + 0x74]; mov eax, esi; mov ecx, dword ptr [esp + 0xa0]; mov byte ptr [esp + 0x73], al; mov byte ptr [edx + ecx], al; inc edx; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0x74], edx; jg 0x41cf85;  
		$rule24 = {d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ce76;  
		$rule25 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 4d 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41cf40;  
		$rule26 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 8b 44 24 18 66 89 55 00 8b 54 24 1c 40 09 14 24 8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov eax, dword ptr [esp + 0x18]; mov word ptr [ebp], dx; mov edx, dword ptr [esp + 0x1c]; inc eax; or dword ptr [esp], edx; mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d5be;  
		$rule27 = {2b 7c 24 48 83 ce 01 4a 75} 
		// sub edi, dword ptr [esp + 0x48]; or esi, 1; dec edx; jne 0x41d55e;  
		$rule28 = {89 44 24 48 b8 00 08 00 00 29 f0 c1 f8 05 8d 04 02 66 89 45 00 8b 44 24 18 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; sar eax, 5; lea eax, [edx + eax]; mov word ptr [ebp], ax; mov eax, dword ptr [esp + 0x18]; jmp 0x41d63b;  
		$rule29 = {8b 4c 24 20 d1 64 24 1c 49 89 4c 24 20 0f85} 
		// mov ecx, dword ptr [esp + 0x20]; shl dword ptr [esp + 0x1c], 1; dec ecx; mov dword ptr [esp + 0x20], ecx; jne 0x41d5be;  
		$rule30 = {89 44 24 48 b8 00 08 00 00 29 f0 89 d6 c1 f8 05 83 7c 24 3c 00 8d 04 01 66 89 85 00 02 00 00 74} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, esi; mov esi, edx; sar eax, 5; cmp dword ptr [esp + 0x3c], 0; lea eax, [ecx + eax]; mov word ptr [ebp + 0x200], ax; je 0x41ced1;  
		$rule31 = {29 44 24 48 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 16 8d 55 01 8b 74 24 28 4e 89 74 24 28 75} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [esi], dx; lea edx, [ebp + 1]; mov esi, dword ptr [esp + 0x28]; dec esi; mov dword ptr [esp + 0x28], esi; jne 0x41d3da;  
		$rule32 = {29 44 24 48 29 c7 89 c8 8d 72 01 66 c1 e8 05 66 29 c1 83 7c 24 3c 00 66 89 8d 00 02 00 00 74} 
		// sub dword ptr [esp + 0x48], eax; sub edi, eax; mov eax, ecx; lea esi, [edx + 1]; shr ax, 5; sub cx, ax; cmp dword ptr [esp + 0x3c], 0; mov word ptr [ebp + 0x200], cx; je 0x41cedf;  
		$rule33 = {8b 4c 24 48 29 c7 8b 74 24 60 29 c1 89 d0 66 c1 e8 05 66 29 c2 81 f9 ff ff ff 00 66 89 55 00 8b 6c 24 78 8d 74 75 00 89 74 24 38 77} 
		// mov ecx, dword ptr [esp + 0x48]; sub edi, eax; mov esi, dword ptr [esp + 0x60]; sub ecx, eax; mov eax, edx; shr ax, 5; sub dx, ax; cmp ecx, 0xffffff; mov word ptr [ebp], dx; mov ebp, dword ptr [esp + 0x78]; lea esi, [ebp + esi*2]; mov dword ptr [esp + 0x38], esi; ja 0x41cfe3;  
		$rule34 = {8a 4c 24 30 b8 01 00 00 00 d3 e0 29 c2 03 54 24 2c 83 7c 24 60 03 89 54 24 0c 0f8f} 
		// mov cl, byte ptr [esp + 0x30]; mov eax, 1; shl eax, cl; sub edx, eax; add edx, dword ptr [esp + 0x2c]; cmp dword ptr [esp + 0x60], 3; mov dword ptr [esp + 0xc], edx; jg 0x41d658;  
		$rule35 = {8b 4c 24 0c 8b 6c 24 74 83 c1 02 39 6c 24 5c 77} 
		// mov ecx, dword ptr [esp + 0xc]; mov ebp, dword ptr [esp + 0x74]; add ecx, 2; cmp dword ptr [esp + 0x5c], ebp; ja 0x41d6c8;  
		$rule36 = {8b 84 24 a0 00 00 00 89 ea 2b 44 24 5c 03 94 24 a0 00 00 00 8d 34 28 8a 06 46 88 44 24 73 88 02 42 ff 44 24 74 49 74} 
		// mov eax, dword ptr [esp + 0xa0]; mov edx, ebp; sub eax, dword ptr [esp + 0x5c]; add edx, dword ptr [esp + 0xa0]; lea esi, [eax + ebp]; mov al, byte ptr [esi]; inc esi; mov byte ptr [esp + 0x73], al; mov byte ptr [edx], al; inc edx; inc dword ptr [esp + 0x74]; dec ecx; je 0x41d6a0;  
		$rule37 = {8b 4c 24 30 ba 01 00 00 00 89 4c 24 28 8d 2c 12 8b 74 24 10 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov ecx, dword ptr [esp + 0x30]; mov edx, 1; mov dword ptr [esp + 0x28], ecx; lea ebp, [edx + edx]; mov esi, dword ptr [esp + 0x10]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d405;  
		$rule38 = {66 8b 11 89 f0 c1 e8 0b 0f b7 ea 0f af c5 39 c7 73} 
		// mov dx, word ptr [ecx]; mov eax, esi; shr eax, 0xb; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d322;  
		$rule39 = {89 44 24 48 b8 00 08 00 00 29 e8 c1 64 24 44 04 c1 f8 05 c7 44 24 2c 00 00 00 00 8d 04 02 66 89 01 8b 44 24 44 8d 4c 01 04 89 4c 24 10 eb} 
		// mov dword ptr [esp + 0x48], eax; mov eax, 0x800; sub eax, ebp; shl dword ptr [esp + 0x44], 4; sar eax, 5; mov dword ptr [esp + 0x2c], 0; lea eax, [edx + eax]; mov word ptr [ecx], ax; mov eax, dword ptr [esp + 0x44]; lea ecx, [ecx + eax + 4]; mov dword ptr [esp + 0x10], ecx; jmp 0x41d394;  
		$rule40 = {8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d04f;  
		$rule41 = {89 c6 b8 00 08 00 00 29 e8 8b 6c 24 58 c1 f8 05 8b 4c 24 54 8d 04 02 8b 54 24 38 89 4c 24 50 8b 4c 24 78 66 89 82 80 01 00 00 8b 44 24 5c 89 6c 24 54 89 44 24 58 31 c0 83 7c 24 60 06 0f 9f c0 81 c1 64 06 00 00 8d 04 40 89 44 24 60 e9} 
		// mov esi, eax; mov eax, 0x800; sub eax, ebp; mov ebp, dword ptr [esp + 0x58]; sar eax, 5; mov ecx, dword ptr [esp + 0x54]; lea eax, [edx + eax]; mov edx, dword ptr [esp + 0x38]; mov dword ptr [esp + 0x50], ecx; mov ecx, dword ptr [esp + 0x78]; mov word ptr [edx + 0x180], ax; mov eax, dword ptr [esp + 0x5c]; mov dword ptr [esp + 0x54], ebp; mov dword ptr [esp + 0x58], eax; xor eax, eax; cmp dword ptr [esp + 0x60], 6; setg al; add ecx, 0x664; lea eax, [eax + eax*2]; mov dword ptr [esp + 0x60], eax; jmp 0x41d2c3;  
		$rule42 = {83 44 24 60 07 83 fa 03 89 d0 7e} 
		// add dword ptr [esp + 0x60], 7; cmp edx, 3; mov eax, edx; jle 0x41d482;  
		$rule43 = {8d 50 c0 83 fa 03 89 14 24 0f8e} 
		// lea edx, [eax - 0x40]; cmp edx, 3; mov dword ptr [esp], edx; jle 0x41d64e;  
		$rule44 = {8b 34 24 46 89 74 24 5c 74} 
		// mov esi, dword ptr [esp]; inc esi; mov dword ptr [esp + 0x5c], esi; je 0x41d6b1;  
		$rule45 = {89 d0 89 d6 d1 f8 83 e6 01 8d 48 ff 83 ce 02 83 fa 0d 89 4c 24 20 7f} 
		// mov eax, edx; mov esi, edx; sar eax, 1; and esi, 1; lea ecx, [eax - 1]; or esi, 2; cmp edx, 0xd; mov dword ptr [esp + 0x20], ecx; jg 0x41d55b;  
		$rule46 = {8b 44 24 74 2b 44 24 5c 8b 94 24 a0 00 00 00 0f b6 04 02 89 44 24 40 d1 64 24 40 8b 4c 24 40 8d 14 36 8b 6c 24 14 81 e1 00 01 00 00 81 7c 24 48 ff ff ff 00 8d 44 4d 00 89 4c 24 3c 8d 2c 10 77} 
		// mov eax, dword ptr [esp + 0x74]; sub eax, dword ptr [esp + 0x5c]; mov edx, dword ptr [esp + 0xa0]; movzx eax, byte ptr [edx + eax]; mov dword ptr [esp + 0x40], eax; shl dword ptr [esp + 0x40], 1; mov ecx, dword ptr [esp + 0x40]; lea edx, [esi + esi]; mov ebp, dword ptr [esp + 0x14]; and ecx, 0x100; cmp dword ptr [esp + 0x48], 0xffffff; lea eax, [ebp + ecx*2]; mov dword ptr [esp + 0x3c], ecx; lea ebp, [eax + edx]; ja 0x41ce76;  
		$rule47 = {66 c7 00 00 04 83 c0 02 } 
		// mov word ptr [eax], 0x400; add eax, 2; loop 0x41cd18;  
		$rule48 = {8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule49 = {8d 50 fb 81 7c 24 48 ff ff ff 00 77} 
		// lea edx, [eax - 5]; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d580;  
		$rule50 = {8b 44 24 78 c1 e6 04 89 34 24 05 44 06 00 00 c7 44 24 20 04 00 00 00 89 44 24 04 c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, dword ptr [esp + 0x78]; shl esi, 4; mov dword ptr [esp], esi; add eax, 0x644; mov dword ptr [esp + 0x20], 4; mov dword ptr [esp + 4], eax; mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule51 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 16 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov dx, word ptr [esi]; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d4f8;  
		$rule52 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 d1 6c 24 48 01 f6 3b 7c 24 48 72} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; shr dword ptr [esp + 0x48], 1; add esi, esi; cmp edi, dword ptr [esp + 0x48]; jb 0x41d593;  
		$rule53 = {50 39 cc 75} 
		// push eax; cmp esp, ecx; jne 0x41d707;  
		$rule54 = {50 39 dc 75} 
		// push eax; cmp esp, ebx; jne 0x41cc48;  
		$rule55 = {89 ce 29 c7 29 c6 89 d0 66 c1 e8 05 8b 4c 24 38 66 29 c2 81 fe ff ff ff 00 66 89 91 80 01 00 00 77} 
		// mov esi, ecx; sub edi, eax; sub esi, eax; mov eax, edx; shr ax, 5; mov ecx, dword ptr [esp + 0x38]; sub dx, ax; cmp esi, 0xffffff; mov word ptr [ecx + 0x180], dx; ja 0x41d087;  
		$rule56 = {8b 6c 24 78 d3 e6 01 d2 89 34 24 8d 44 75 00 29 d0 05 5e 05 00 00 89 44 24 04 eb} 
		// mov ebp, dword ptr [esp + 0x78]; shl esi, cl; add edx, edx; mov dword ptr [esp], esi; lea eax, [ebp + esi*2]; sub eax, edx; add eax, 0x55e; mov dword ptr [esp + 4], eax; jmp 0x41d5b1;  
		$rule57 = {c7 44 24 1c 01 00 00 00 b8 01 00 00 00 8b 6c 24 04 01 c0 89 44 24 18 01 c5 81 7c 24 48 ff ff ff 00 77} 
		// mov dword ptr [esp + 0x1c], 1; mov eax, 1; mov ebp, dword ptr [esp + 4]; add eax, eax; mov dword ptr [esp + 0x18], eax; add ebp, eax; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d5ec;  
		$rule58 = {8b 6c 24 38 89 f2 c1 ea 0b 66 8b 8d 98 01 00 00 0f b7 c1 0f af d0 39 d7 0f83} 
		// mov ebp, dword ptr [esp + 0x38]; mov edx, esi; shr edx, 0xb; mov cx, word ptr [ebp + 0x198]; movzx eax, cx; imul edx, eax; cmp edi, edx; jae 0x41d188;  
		$rule59 = {b8 03 00 00 00 8b 74 24 78 c1 e0 07 c7 44 24 24 06 00 00 00 8d 84 06 60 03 00 00 89 44 24 08 b8 01 00 00 00 8d 2c 00 8b 74 24 08 01 ee 81 7c 24 48 ff ff ff 00 77} 
		// mov eax, 3; mov esi, dword ptr [esp + 0x78]; shl eax, 7; mov dword ptr [esp + 0x24], 6; lea eax, [esi + eax + 0x360]; mov dword ptr [esp + 8], eax; mov eax, 1; lea ebp, [eax + eax]; mov esi, dword ptr [esp + 8]; add esi, ebp; cmp dword ptr [esp + 0x48], 0xffffff; ja 0x41d4cc;  
		$rule60 = {bd 00 08 00 00 89 d6 29 c5 c7 44 24 34 00 08 00 00 89 e8 c1 f8 05 8d 04 01 8b 4c 24 38 66 89 81 98 01 00 00 8b 44 24 60 8b 4c 24 44 c1 e0 05 03 44 24 78 81 fa ff ff ff 00 8d 2c 48 77} 
		// mov ebp, 0x800; mov esi, edx; sub ebp, eax; mov dword ptr [esp + 0x34], 0x800; mov eax, ebp; sar eax, 5; lea eax, [ecx + eax]; mov ecx, dword ptr [esp + 0x38]; mov word ptr [ecx + 0x198], ax; mov eax, dword ptr [esp + 0x60]; mov ecx, dword ptr [esp + 0x44]; shl eax, 5; add eax, dword ptr [esp + 0x78]; cmp edx, 0xffffff; lea ebp, [eax + ecx*2]; ja 0x41d0f9;  
		$rule61 = {29 c6 29 c7 89 d0 66 c1 e8 05 66 29 c2 66 89 95 e0 01 00 00 e9} 
		// sub esi, eax; sub edi, eax; mov eax, edx; shr ax, 5; sub dx, ax; mov word ptr [ebp + 0x1e0], dx; jmp 0x41d2a7;  
		$rule62 = {31 c0 83 7c 24 60 06 8b 4c 24 78 0f 9f c0 81 c1 68 0a 00 00 8d 44 40 08 89 44 24 60 81 fe ff ff ff 00 77} 
		// xor eax, eax; cmp dword ptr [esp + 0x60], 6; mov ecx, dword ptr [esp + 0x78]; setg al; add ecx, 0xa68; lea eax, [eax + eax*2 + 8]; mov dword ptr [esp + 0x60], eax; cmp esi, 0xffffff; ja 0x41d2e1;  
		$rule63 = {66 8b 95 e0 01 00 00 89 f0 c1 e8 0b 0f b7 ca 0f af c1 39 c7 73} 
		// mov dx, word ptr [ebp + 0x1e0]; mov eax, esi; shr eax, 0xb; movzx ecx, dx; imul eax, ecx; cmp edi, eax; jae 0x41d16f;  
		$rule64 = {0f b6 03 c1 e7 08 c1 e1 08 43 09 c7 8b 6c 24 38 89 c8 c1 e8 0b 66 8b 95 80 01 00 00 0f b7 ea 0f af c5 39 c7 73} 
		// movzx eax, byte ptr [ebx]; shl edi, 8; shl ecx, 8; inc ebx; or edi, eax; mov ebp, dword ptr [esp + 0x38]; mov eax, ecx; shr eax, 0xb; mov dx, word ptr [ebp + 0x180]; movzx ebp, dx; imul eax, ebp; cmp edi, eax; jae 0x41d04f;  
		$rule65 = {c1 64 24 48 08 0f b6 03 c1 e7 08 43 09 c7 8b 44 24 48 66 8b 8d 00 02 00 00 c1 e8 0b 0f b7 f1 0f af c6 39 c7 73} 
		// shl dword ptr [esp + 0x48], 8; movzx eax, byte ptr [ebx]; shl edi, 8; inc ebx; or edi, eax; mov eax, dword ptr [esp + 0x48]; mov cx, word ptr [ebp + 0x200]; shr eax, 0xb; movzx esi, cx; imul eax, esi; cmp edi, eax; jae 0x41ceb1;  
		
	condition:
		pe.is_32bit() and (46 of them) and (pe.overlay.offset == 0 or for 32 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v309_nrv2e_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v309"
		config="nrv2e_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41cd92;  
		$rule1 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41cce4;  
		$rule2 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41ccc1;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41cd74;  
		$rule4 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41ccd3;  
		$rule5 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41cd1b;  
		$rule6 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41cd8a;  
		$rule7 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41cd26;  
		$rule8 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41ccf0;  
		$rule9 = {81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cd74;  
		$rule10 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41cd34;  
		$rule11 = {11 c9 01 db 73} 
		// adc ecx, ecx; add ebx, ebx; jae 0x41cd36;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 02 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 2; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41cd74;  
		$rule13 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41cd97;  
		$rule14 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41ccb0;  
		$rule15 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41cce4;  
		$rule16 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41cd66;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41ccc8;  
		
	condition:
		pe.is_32bit() and (12 of them) and (pe.overlay.offset == 0 or for 8 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Upx_v309_nrv2d_1_combined
{
	meta:
		packer="Upx"
		generator="PackGenome"
		version="v309"
		config="nrv2d_1"
	strings:
		$rule0 = {8a 07 47 2c e8 3c 01 77} 
		// mov al, byte ptr [edi]; inc edi; sub al, 0xe8; cmp al, 1; ja 0x41c20e;  
		$rule1 = {8a 06 46 88 07 47 01 db 75} 
		// mov al, byte ptr [esi]; inc esi; mov byte ptr [edi], al; inc edi; add ebx, ebx; jne 0x41c149;  
		$rule2 = {11 c0 01 db 73} 
		// adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule3 = {8b 02 83 c2 04 89 07 83 c7 04 83 e9 04 77} 
		// mov eax, dword ptr [edx]; add edx, 4; mov dword ptr [edi], eax; add edi, 4; sub ecx, 4; ja 0x41c1f0;  
		$rule4 = {48 01 db 75} 
		// dec eax; add ebx, ebx; jne 0x41c178;  
		$rule5 = {b8 01 00 00 00 01 db 75} 
		// mov eax, 1; add ebx, ebx; jne 0x41c15b;  
		$rule6 = {31 c9 83 e8 03 72} 
		// xor ecx, ecx; sub eax, 3; jb 0x41c194;  
		$rule7 = {11 c9 01 db 75} 
		// adc ecx, ecx; add ebx, ebx; jne 0x41c1ac;  
		$rule8 = {c1 e0 08 8a 06 46 83 f0 ff 74} 
		// shl eax, 8; mov al, byte ptr [esi]; inc esi; xor eax, 0xffffffff; je 0x41c206;  
		$rule9 = {d1 f8 89 c5 eb} 
		// sar eax, 1; mov ebp, eax; jmp 0x41c19f;  
		$rule10 = {81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule11 = {41 01 db 75} 
		// inc ecx; add ebx, ebx; jne 0x41c1bc;  
		$rule12 = {83 c1 02 81 fd 00 fb ff ff 83 d1 01 8d 14 2f 83 fd fc 76} 
		// add ecx, 2; cmp ebp, 0xfffffb00; adc ecx, 1; lea edx, [edi + ebp]; cmp ebp, -4; jbe 0x41c1f0;  
		$rule13 = {8a 02 42 88 07 47 49 75} 
		// mov al, byte ptr [edx]; inc edx; mov byte ptr [edi], al; inc edi; dec ecx; jne 0x41c1e1;  
		$rule14 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 } 
		// mov eax, dword ptr [edi]; mov bl, byte ptr [edi + 4]; shr ax, 8; rol eax, 0x10; xchg ah, al; sub eax, edi; sub bl, 0xe8; add eax, esi; mov dword ptr [edi], eax; add edi, 5; mov al, bl; loop 0x41c213;  
		$rule15 = {8b 1e 83 ee fc 11 db 72} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; jb 0x41c138;  
		$rule16 = {8b 1e 83 ee fc 11 db 11 c0 01 db 73} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; add ebx, ebx; jae 0x41c16c;  
		$rule17 = {8b 1e 83 ee fc 11 db 11 c0 eb} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc eax, eax; jmp 0x41c150;  
		$rule18 = {8b 1e 83 ee fc 11 db 11 c9 75} 
		// mov ebx, dword ptr [esi]; sub esi, -4; adc ebx, ebx; adc ecx, ecx; jne 0x41c1d0;  
		
	condition:
		pe.is_32bit() and (13 of them) and (pe.overlay.offset == 0 or for 9 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// Armadillo
rule packer_Armadillo_v700
{
	meta:
		packer="Armadillo"
		generator="PackGenome"
		version="v700"
		configs="best_full minimal best_resources best better"
	strings:
		$rule0 = {40 30 18 49 75} 
		// inc eax; xor byte ptr [eax], bl; dec ecx; jne 0x48c173;  
		$rule1 = {81 c3 01 01 01 01 31 18 81 38 78 54 00 00 74} 
		// add ebx, 0x1010101; xor dword ptr [eax], ebx; cmp dword ptr [eax], 0x5478; je 0x48c165;  
		$rule2 = {31 18 eb} 
		// xor dword ptr [eax], ebx; jmp 0x48c151;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Armadillo_v800_alsr_minimal_combined
{
	meta:
		packer="Armadillo"
		generator="PackGenome"
		version="v800_alsr"
		config="minimal"
	strings:
		$rule0 = {03 c5 66 39 18 75} 
		// add eax, ebp; cmp word ptr [eax], bx; jne 0x4974a5;  
		$rule1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74} 
		// mov eax, dword ptr [ecx]; mov edx, 0x7efefeff; add edx, eax; xor eax, 0xffffffff; xor eax, edx; add ecx, 4; test eax, 0x81010100; je 0x487dc0;  
		$rule2 = {40 3b cb 75} 
		// inc eax; cmp ecx, ebx; jne 0x490bcc;  
		$rule3 = {49 38 18 74} 
		// dec ecx; cmp byte ptr [eax], bl; je 0x490bd9;  
		$rule4 = {89 45 e4 3d 01 01 00 00 7d} 
		// mov dword ptr [ebp - 0x1c], eax; cmp eax, 0x101; jge 0x493bbb;  
		$rule5 = {8a 4c 18 1c 88 88 a0 f0 4d 00 40 eb} 
		// mov cl, byte ptr [eax + ebx + 0x1c]; mov byte ptr [eax + 0x4df0a0], cl; inc eax; jmp 0x493ba4;  
		$rule6 = {89 45 e4 3d 00 01 00 00 7d} 
		// mov dword ptr [ebp - 0x1c], eax; cmp eax, 0x100; jge 0x493bd7;  
		$rule7 = {8a 8c 18 1d 01 00 00 88 88 a8 f1 4d 00 40 eb} 
		// mov cl, byte ptr [eax + ebx + 0x11d]; mov byte ptr [eax + 0x4df1a8], cl; inc eax; jmp 0x493bbd;  
		$rule8 = {88 84 05 98 03 00 00 40 3b c7 72} 
		// mov byte ptr [ebp + eax + 0x398], al; inc eax; cmp eax, edi; jb 0x49362c;  
		$rule9 = {0f b7 4c 45 98 f6 c1 01 74} 
		// movzx ecx, word ptr [ebp + eax*2 - 0x68]; test cl, 1; je 0x4936f0;  
		$rule10 = {8a 01 83 c1 01 84 c0 74} 
		// mov al, byte ptr [ecx]; add ecx, 1; test al, al; je 0x487df3;  
		$rule11 = {c6 84 06 1d 01 00 00 00 40 3b c7 72} 
		// mov byte ptr [esi + eax + 0x11d], 0; inc eax; cmp eax, edi; jb 0x4936d8;  
		$rule12 = {8b 4c 24 04 f7 c1 03 00 00 00 74} 
		// mov ecx, dword ptr [esp + 4]; test ecx, 3; je 0x487dc0;  
		$rule13 = {8b 41 fc 84 c0 74} 
		// mov eax, dword ptr [ecx - 4]; test al, al; je 0x487e11;  
		$rule14 = {68 90 96 48 00 64 ff 35 00 00 00 00 8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 b0 e8 4d 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3 00 00 00 00 c3} 
		// push 0x489690; push dword ptr fs:[0]; mov eax, dword ptr [esp + 0x10]; mov dword ptr [esp + 0x10], ebp; lea ebp, [esp + 0x10]; sub esp, eax; push ebx; push esi; push edi; mov eax, dword ptr [0x4de8b0]; xor dword ptr [ebp - 4], eax; xor eax, ebp; push eax; mov dword ptr [ebp - 0x18], esp; push dword ptr [ebp - 8]; mov eax, dword ptr [ebp - 4]; mov dword ptr [ebp - 4], 0xfffffffe; mov dword ptr [ebp - 8], eax; lea eax, [ebp - 0x10]; mov dword ptr fs:[0], eax; ret ;  
		$rule15 = {05 00 00 00 00 8d a4 24 00 00 00 00 8d a4 24 00 00 00 00 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74} 
		// add eax, 0; lea esp, [esp]; lea esp, [esp]; mov eax, dword ptr [ecx]; mov edx, 0x7efefeff; add edx, eax; xor eax, 0xffffffff; xor eax, edx; add ecx, 4; test eax, 0x81010100; je 0x487dc0;  
		$rule16 = {56 57 33 f6 6a 00 ff 74 24 14 ff 74 24 14 e8} 
		// push esi; push edi; xor esi, esi; push 0; push dword ptr [esp + 0x14]; push dword ptr [esp + 0x14]; call 0x49b8ae;  
		$rule17 = {6a 0c 68 d8 3a 4f 00 e8} 
		// push 0xc; push 0x4f3ad8; call 0x4933f0;  
		$rule18 = {47 56 e8} 
		// inc edi; push esi; call 0x487d90;  
		$rule19 = {59 8d 74 06 01 8a 06 3a c3 75} 
		// pop ecx; lea esi, [esi + eax + 1]; mov al, byte ptr [esi]; cmp al, bl; jne 0x497129;  
		$rule20 = {8b e8 45 80 3e 3d 59 74} 
		// mov ebp, eax; inc ebp; cmp byte ptr [esi], 0x3d; pop ecx; je 0x49719d;  
		$rule21 = {6a 01 55 e8} 
		// push 1; push ebp; call 0x490fef;  
		$rule22 = {83 c4 0c 85 c0 74} 
		// add esp, 0xc; test eax, eax; je 0x49719a;  
		$rule23 = {83 c7 04 03 f5 38 1e 75} 
		// add edi, 4; add esi, ebp; cmp byte ptr [esi], bl; jne 0x49715f;  
		$rule24 = {56 ff 35 9c f4 4d 00 8b 35 e4 c1 4d 00 ff} 
		// push esi; push dword ptr [0x4df49c]; mov esi, dword ptr [0x4dc1e4]; call esi;  
		$rule25 = {40 3b c7 72} 
		// inc eax; cmp eax, edi; jb 0x4936d8;  
		$rule26 = {8d 41 fe 8b 4c 24 04 2b c1 c3} 
		// lea eax, [ecx - 2]; mov ecx, dword ptr [esp + 4]; sub eax, ecx; ret ;  
		$rule27 = {8b 44 24 04 85 c0 56 8b f1 c6 46 0c 00 75} 
		// mov eax, dword ptr [esp + 4]; test eax, eax; push esi; mov esi, ecx; mov byte ptr [esi + 0xc], 0; jne 0x48763a;  
		$rule28 = {56 57 ff} 
		// push esi; push edi; call dword ptr [0x4dc030];  
		$rule29 = {8d 41 ff 8b 4c 24 04 2b c1 c3} 
		// lea eax, [ecx - 1]; mov ecx, dword ptr [esp + 4]; sub eax, ecx; ret ;  
		$rule30 = {83 ec 14 53 8b 5c 24 20 55 56 8b 73 08 33 35 b0 e8 4d 00 57 8b 06 83 f8 fe c6 44 24 13 00 c7 44 24 18 01 00 00 00 8d 7b 10 74} 
		// sub esp, 0x14; push ebx; mov ebx, dword ptr [esp + 0x20]; push ebp; push esi; mov esi, dword ptr [ebx + 8]; xor esi, dword ptr [0x4de8b0]; push edi; mov eax, dword ptr [esi]; cmp eax, -2; mov byte ptr [esp + 0x13], 0; mov dword ptr [esp + 0x18], 1; lea edi, [ebx + 0x10]; je 0x4896c8;  
		$rule31 = {8b 4e 0c 8b 46 08 03 cf 33 0c 38 e8} 
		// mov ecx, dword ptr [esi + 0xc]; mov eax, dword ptr [esi + 8]; add ecx, edi; xor ecx, dword ptr [eax + edi]; call 0x4883c2;  
		$rule32 = {8b 44 24 2c 39 68 0c 74} 
		// mov eax, dword ptr [esp + 0x2c]; cmp dword ptr [eax + 0xc], ebp; je 0x4897d0;  
		$rule33 = {8b 4c 24 14 89 48 0c 8b 06 83 f8 fe 74} 
		// mov ecx, dword ptr [esp + 0x14]; mov dword ptr [eax + 0xc], ecx; mov eax, dword ptr [esi]; cmp eax, -2; je 0x4897eb;  
		$rule34 = {8b 4e 0c 8b 56 08 03 cf 33 0c 3a e8} 
		// mov ecx, dword ptr [esi + 0xc]; mov edx, dword ptr [esi + 8]; add ecx, edi; xor ecx, dword ptr [edx + edi]; call 0x4883c2;  
		$rule35 = {8b 4b 08 8b d7 e9} 
		// mov ecx, dword ptr [ebx + 8]; mov edx, edi; jmp 0x497b5d;  
		$rule36 = {8b ea 8b f1 8b c1 6a 01 e8} 
		// mov ebp, edx; mov esi, ecx; mov eax, ecx; push 1; call 0x49de99;  
		$rule37 = {53 51 bb 7c f9 4d 00 8b 4c 24 0c 89 4b 08 89 43 04 89 6b 0c 55 51 50 58 59 5d 59 5b } 
		// push ebx; push ecx; mov ebx, 0x4df97c; mov ecx, dword ptr [esp + 0xc]; mov dword ptr [ebx + 8], ecx; mov dword ptr [ebx + 4], eax; mov dword ptr [ebx + 0xc], ebp; push ebp; push ecx; push eax; pop eax; pop ecx; pop ebp; pop ecx; pop ebx; ret 4;  
		$rule38 = {8d 41 fc 8b 4c 24 04 2b c1 c3} 
		// lea eax, [ecx - 4]; mov ecx, dword ptr [esp + 4]; sub eax, ecx; ret ;  
		$rule39 = {8d 41 fd 8b 4c 24 04 2b c1 c3} 
		// lea eax, [ecx - 3]; mov ecx, dword ptr [esp + 4]; sub eax, ecx; ret ;  
		$rule40 = {ff 07 85 d2 74} 
		// inc dword ptr [edi]; test edx, edx; je 0x497234;  
		$rule41 = {85 c0 59 74} 
		// test eax, eax; pop ecx; je 0x497258;  
		$rule42 = {84 db 8b 55 0c 8b 4d 10 74} 
		// test bl, bl; mov edx, dword ptr [ebp + 0xc]; mov ecx, dword ptr [ebp + 0x10]; je 0x497294;  
		$rule43 = {55 8b ec 83 ec 10 ff 75 08 8d 4d f0 e8} 
		// push ebp; mov ebp, esp; sub esp, 0x10; push dword ptr [ebp + 8]; lea ecx, [ebp - 0x10]; call 0x4875c8;  
		$rule44 = {6a 04 6a 00 ff 74 24 0c 6a 00 e8} 
		// push 4; push 0; push dword ptr [esp + 0xc]; push 0; call 0x4a3e0f;  
		$rule45 = {0f b7 06 66 89 02 42 42 46 46 66 3b c7 74} 
		// movzx eax, word ptr [esi]; mov word ptr [edx], ax; inc edx; inc edx; inc esi; inc esi; cmp ax, di; je 0x48d074;  
		$rule46 = {46 83 fe 24 7c} 
		// inc esi; cmp esi, 0x24; jl 0x495d5d;  
		$rule47 = {8b 45 fc 83 c0 04 89 45 f8 8b 45 f8 8b e5 5d c3} 
		// mov eax, dword ptr [ebp - 4]; add eax, 4; mov dword ptr [ebp - 8], eax; mov eax, dword ptr [ebp - 8]; mov esp, ebp; pop ebp; ret ;  
		$rule48 = {c6 40 04 00 83 08 ff c6 40 05 0a 89 78 08 c6 40 24 00 c6 40 25 0a c6 40 26 0a 89 78 38 c6 40 34 00 83 c0 40 8b 0d 80 60 4f 00 81 c1 00 08 00 00 3b c1 72} 
		// mov byte ptr [eax + 4], 0; or dword ptr [eax], 0xffffffff; mov byte ptr [eax + 5], 0xa; mov dword ptr [eax + 8], edi; mov byte ptr [eax + 0x24], 0; mov byte ptr [eax + 0x25], 0xa; mov byte ptr [eax + 0x26], 0xa; mov dword ptr [eax + 0x38], edi; mov byte ptr [eax + 0x34], 0; add eax, 0x40; mov ecx, dword ptr [0x4f6080]; add ecx, 0x800; cmp eax, ecx; jb 0x4975b8;  
		$rule49 = {80 4c 06 1d 10 8a 8c 05 98 02 00 00 eb} 
		// or byte ptr [esi + eax + 0x1d], 0x10; mov cl, byte ptr [ebp + eax + 0x298]; jmp 0x493701;  
		$rule50 = {80 4c 06 1d 20 8a 8c 05 98 01 00 00 88 8c 06 1d 01 00 00 eb} 
		// or byte ptr [esi + eax + 0x1d], 0x20; mov cl, byte ptr [ebp + eax + 0x198]; mov byte ptr [esi + eax + 0x11d], cl; jmp 0x493712;  
		$rule51 = {55 8b ec 8b 45 08 ff 34 c5 a0 f5 4d 00 ff} 
		// push ebp; mov ebp, esp; mov eax, dword ptr [ebp + 8]; push dword ptr [eax*8 + 0x4df5a0]; call dword ptr [0x4dc224];  
		$rule52 = {a1 ac 61 4f 00 89 0c 02 83 c1 20 83 c2 04 81 f9 78 ee 4d 00 7c} 
		// mov eax, dword ptr [0x4f61ac]; mov dword ptr [edx + eax], ecx; add ecx, 0x20; add edx, 4; cmp ecx, 0x4dee78; jl 0x492786;  
		$rule53 = {8a 06 88 02 42 89 55 0c 8a 1e 0f b6 c3 50 46 e8} 
		// mov al, byte ptr [esi]; mov byte ptr [edx], al; inc edx; mov dword ptr [ebp + 0xc], edx; mov bl, byte ptr [esi]; movzx eax, bl; push eax; inc esi; call 0x4a3fcd;  
		$rule54 = {8a 1e 0f b6 c3 50 46 e8} 
		// mov bl, byte ptr [esi]; movzx eax, bl; push eax; inc esi; call 0x4a3fcd;  
		
	condition:
		pe.is_32bit() and (38 of them) and (pe.overlay.offset == 0 or for 26 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Armadillo_v800_alsr_better_combined
{
	meta:
		packer="Armadillo"
		generator="PackGenome"
		version="v800_alsr"
		configs="better best best_resources"
	strings:
		$rule0 = {29 55 14 8b da c1 e3 02 2b cb 83 7d 14 00 8b 5d 18 89 19 75} 
		// sub dword ptr [ebp + 0x14], edx; mov ebx, edx; shl ebx, 2; sub ecx, ebx; cmp dword ptr [ebp + 0x14], 0; mov ebx, dword ptr [ebp + 0x18]; mov dword ptr [ecx], ebx; jne 0x4b2669;  
		$rule1 = {0f b7 04 4b 8d 44 45 3c 66 ff 00 41 3b 4d 70 72} 
		// movzx eax, word ptr [ebx + ecx*2]; lea eax, [ebp + eax*2 + 0x3c]; inc word ptr [eax]; inc ecx; cmp ecx, dword ptr [ebp + 0x70]; jb 0x4b2478;  
		$rule2 = {0f b7 04 7b 0f b7 44 45 1c 8b 4d 14 66 89 3c 41 0f b7 0c 7b 8d 4c 4d 1c 66 ff 01 47 3b 7d 70 72} 
		// movzx eax, word ptr [ebx + edi*2]; movzx eax, word ptr [ebp + eax*2 + 0x1c]; mov ecx, dword ptr [ebp + 0x14]; mov word ptr [ecx + eax*2], di; movzx ecx, word ptr [ebx + edi*2]; lea ecx, [ebp + ecx*2 + 0x1c]; inc word ptr [ecx]; inc edi; cmp edi, dword ptr [ebp + 0x70]; jb 0x4b253f;  
		$rule3 = {33 d2 8d 48 ff 42 d3 e2 8b 4d fc eb} 
		// xor edx, edx; lea ecx, [eax - 1]; inc edx; shl edx, cl; mov ecx, dword ptr [ebp - 4]; jmp 0x4b268d;  
		$rule4 = {33 d2 8b c8 2b 4d 10 42 d3 e2 8b 4d f8 89 4d 14 89 4d 0c 8b 4d 10 d3 eb 03 5d 14 8d 0c 9f 29 55 14 8b da c1 e3 02 2b cb 83 7d 14 00 8b 5d 18 89 19 75} 
		// xor edx, edx; mov ecx, eax; sub ecx, dword ptr [ebp + 0x10]; inc edx; shl edx, cl; mov ecx, dword ptr [ebp - 8]; mov dword ptr [ebp + 0x14], ecx; mov dword ptr [ebp + 0xc], ecx; mov ecx, dword ptr [ebp + 0x10]; shr ebx, cl; add ebx, dword ptr [ebp + 0x14]; lea ecx, [edi + ebx*4]; sub dword ptr [ebp + 0x14], edx; mov ebx, edx; shl ebx, 2; sub ecx, ebx; cmp dword ptr [ebp + 0x14], 0; mov ebx, dword ptr [ebp + 0x18]; mov dword ptr [ecx], ebx; jne 0x4b2669;  
		$rule5 = {8a c8 2a 4d 10 88 4d 19 8b 4d 04 0f b7 11 0f b7 ca 3b 4d f0 7d} 
		// mov cl, al; sub cl, byte ptr [ebp + 0x10]; mov byte ptr [ebp + 0x19], cl; mov ecx, dword ptr [ebp + 4]; movzx edx, word ptr [ecx]; movzx ecx, dx; cmp ecx, dword ptr [ebp - 0x10]; jge 0x4b2622;  
		$rule6 = {d1 ea 85 d1 75} 
		// shr edx, 1; test ecx, edx; jne 0x4b268b;  
		$rule7 = {8d 5a ff 23 d9 03 da eb} 
		// lea ebx, [edx - 1]; and ebx, ecx; add ebx, edx; jmp 0x4b26a0;  
		$rule8 = {83 45 04 02 8d 4c 45 3c 66 ff 09 0f b7 09 66 85 c9 89 5d fc 75} 
		// add dword ptr [ebp + 4], 2; lea ecx, [ebp + eax*2 + 0x3c]; dec word ptr [ecx]; movzx ecx, word ptr [ecx]; test cx, cx; mov dword ptr [ebp - 4], ebx; jne 0x4b26cf;  
		$rule9 = {8b 55 08 3b c2 0f86} 
		// mov edx, dword ptr [ebp + 8]; cmp eax, edx; jbe 0x4b2602;  
		$rule10 = {c6 45 18 00 66 89 55 1a eb} 
		// mov byte ptr [ebp + 0x18], 0; mov word ptr [ebp + 0x1a], dx; jmp 0x4b264b;  
		$rule11 = {03 c5 66 39 18 75} 
		// add eax, ebp; cmp word ptr [eax], bx; jne 0x4974a5;  
		$rule12 = {8b 4d dc 23 cb 3b 4d ec 89 4d 14 0f84} 
		// mov ecx, dword ptr [ebp - 0x24]; and ecx, ebx; cmp ecx, dword ptr [ebp - 0x14]; mov dword ptr [ebp + 0x14], ecx; je 0x4b2602;  
		$rule13 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74} 
		// mov eax, dword ptr [ecx]; mov edx, 0x7efefeff; add edx, eax; xor eax, 0xffffffff; xor eax, edx; add ecx, 4; test eax, 0x81010100; je 0x487dc0;  
		$rule14 = {8b 4d 04 0f b7 09 8b 55 e8 03 c9 8a 14 11 88 55 18 8b 55 e4 66 8b 0c 11 66 89 4d 1a eb} 
		// mov ecx, dword ptr [ebp + 4]; movzx ecx, word ptr [ecx]; mov edx, dword ptr [ebp - 0x18]; add ecx, ecx; mov dl, byte ptr [ecx + edx]; mov byte ptr [ebp + 0x18], dl; mov edx, dword ptr [ebp - 0x1c]; mov cx, word ptr [ecx + edx]; mov word ptr [ebp + 0x1a], cx; jmp 0x4b264b;  
		$rule15 = {33 c0 40 8b d0 d3 e2 01 55 00 39 45 68 89 55 f8 75} 
		// xor eax, eax; inc eax; mov edx, eax; shl edx, cl; add dword ptr [ebp], edx; cmp dword ptr [ebp + 0x68], eax; mov dword ptr [ebp - 8], edx; jne 0x4b2754;  
		$rule16 = {8b 45 14 8b 5d fc 8b d0 89 45 ec 8b 06 c1 e2 02 88 0c 02 8b 06 8a 4d 08 88 4c 02 01 8b 06 8b cf 2b c8 c1 f9 02 66 89 4c 02 02 8b 45 e0 e9} 
		// mov eax, dword ptr [ebp + 0x14]; mov ebx, dword ptr [ebp - 4]; mov edx, eax; mov dword ptr [ebp - 0x14], eax; mov eax, dword ptr [esi]; shl edx, 2; mov byte ptr [edx + eax], cl; mov eax, dword ptr [esi]; mov cl, byte ptr [ebp + 8]; mov byte ptr [edx + eax + 1], cl; mov eax, dword ptr [esi]; mov ecx, edi; sub ecx, eax; sar ecx, 2; mov word ptr [edx + eax + 2], cx; mov eax, dword ptr [ebp - 0x20]; jmp 0x4b2602;  
		$rule17 = {89 45 0c 8d 44 45 3c eb} 
		// mov dword ptr [ebp + 0xc], eax; lea eax, [ebp + eax*2 + 0x3c]; jmp 0x4b2719;  
		$rule18 = {0f b7 18 2b d3 85 d2 7e} 
		// movzx ebx, word ptr [eax]; sub edx, ebx; test edx, edx; jle 0x4b2735;  
		$rule19 = {8b 4d 0c 8d 3c 8f 8b c8 8b 45 10 33 d2 2b c8 42 03 c1 d3 e2 3b 45 f4 73} 
		// mov ecx, dword ptr [ebp + 0xc]; lea edi, [edi + ecx*4]; mov ecx, eax; mov eax, dword ptr [ebp + 0x10]; xor edx, edx; sub ecx, eax; inc edx; add eax, ecx; shl edx, cl; cmp eax, dword ptr [ebp - 0xc]; jae 0x4b2735;  
		$rule20 = {41 83 f9 0f 76} 
		// inc ecx; cmp ecx, 0xf; jbe 0x4b24fa;  
		$rule21 = {0f b7 54 4d 3c 03 ff 2b fa 78} 
		// movzx edx, word ptr [ebp + ecx*2 + 0x3c]; add edi, edi; sub edi, edx; js 0x4b2584;  
		$rule22 = {66 8b 44 0d 1c 66 03 44 0d 3c 41 66 89 44 0d 1d 41 83 f9 1e 72} 
		// mov ax, word ptr [ebp + ecx + 0x1c]; add ax, word ptr [ebp + ecx + 0x3c]; inc ecx; mov word ptr [ebp + ecx + 0x1d], ax; inc ecx; cmp ecx, 0x1e; jb 0x4b2522;  
		$rule23 = {8b 45 04 0f b7 00 8b 4d d4 0f b7 04 41 89 45 e0 8b 55 08 3b c2 0f86} 
		// mov eax, dword ptr [ebp + 4]; movzx eax, word ptr [eax]; mov ecx, dword ptr [ebp - 0x2c]; movzx eax, word ptr [ecx + eax*2]; mov dword ptr [ebp - 0x20], eax; mov edx, dword ptr [ebp + 8]; cmp eax, edx; jbe 0x4b2602;  
		$rule24 = {40 3b cb 75} 
		// inc eax; cmp ecx, ebx; jne 0x490bcc;  
		$rule25 = {49 38 18 74} 
		// dec ecx; cmp byte ptr [eax], bl; je 0x490bd9;  
		$rule26 = {48 83 f8 01 89 45 f4 73} 
		// dec eax; cmp eax, 1; mov dword ptr [ebp - 0xc], eax; jae 0x4b2494;  
		$rule27 = {47 3b 7d 70 72} 
		// inc edi; cmp edi, dword ptr [ebp + 0x70]; jb 0x4b253f;  
		$rule28 = {8a 01 83 c1 01 84 c0 74} 
		// mov al, byte ptr [ecx]; add ecx, 1; test al, al; je 0x487df3;  
		$rule29 = {89 45 e4 3d 01 01 00 00 7d} 
		// mov dword ptr [ebp - 0x1c], eax; cmp eax, 0x101; jge 0x493bbb;  
		$rule30 = {8a 4c 18 1c 88 88 a0 f0 4d 00 40 eb} 
		// mov cl, byte ptr [eax + ebx + 0x1c]; mov byte ptr [eax + 0x4df0a0], cl; inc eax; jmp 0x493ba4;  
		$rule31 = {89 45 e4 3d 00 01 00 00 7d} 
		// mov dword ptr [ebp - 0x1c], eax; cmp eax, 0x100; jge 0x493bd7;  
		$rule32 = {8a 8c 18 1d 01 00 00 88 88 a8 f1 4d 00 40 eb} 
		// mov cl, byte ptr [eax + ebx + 0x11d]; mov byte ptr [eax + 0x4df1a8], cl; inc eax; jmp 0x493bbd;  
		$rule33 = {88 84 05 98 03 00 00 40 3b c7 72} 
		// mov byte ptr [ebp + eax + 0x398], al; inc eax; cmp eax, edi; jb 0x49362c;  
		$rule34 = {0f b7 4c 45 98 f6 c1 01 74} 
		// movzx ecx, word ptr [ebp + eax*2 - 0x68]; test cl, 1; je 0x4936f0;  
		$rule35 = {c6 84 06 1d 01 00 00 00 40 3b c7 72} 
		// mov byte ptr [esi + eax + 0x11d], 0; inc eax; cmp eax, edi; jb 0x4936d8;  
		
	condition:
		pe.is_32bit() and (25 of them) and (pe.overlay.offset == 0 or for 17 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Armadillo_v604
{
	meta:
		packer="Armadillo"
		generator="PackGenome"
		version="v604"
		configs="best_full minimal best_resources best better"
	strings:
		$rule0 = {40 30 18 49 75} 
		// inc eax; xor byte ptr [eax], bl; dec ecx; jne 0x45c173;  
		$rule1 = {81 c3 01 01 01 01 31 18 81 38 78 54 00 00 74} 
		// add ebx, 0x1010101; xor dword ptr [eax], ebx; cmp dword ptr [eax], 0x5478; je 0x45c165;  
		$rule2 = {31 18 eb} 
		// xor dword ptr [eax], ebx; jmp 0x45c151;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Armadillo_v800
{
	meta:
		packer="Armadillo"
		generator="PackGenome"
		version="v800"
		configs="minimal best_resources best better"
	strings:
		$rule0 = {40 30 18 49 75} 
		// inc eax; xor byte ptr [eax], bl; dec ecx; jne 0x4cc173;  
		$rule1 = {81 c3 01 01 01 01 31 18 81 38 78 54 00 00 74} 
		// add ebx, 0x1010101; xor dword ptr [eax], ebx; cmp dword ptr [eax], 0x5478; je 0x4cc165;  
		$rule2 = {31 18 eb} 
		// xor dword ptr [eax], ebx; jmp 0x4cc151;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


