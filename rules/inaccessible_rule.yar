import "pe"
import "dotnet"

// Packman
rule packer_Packman_0
{
meta:
		packer="Packman"
		generator="PackGenome"
		index="0"
	strings:
		$rule0 = {8a 16 46 12 d2 c3} 
		// mov dl, byte ptr [esi]; inc esi; adc dl, dl; ret ;  
		$rule1 = {a4 b3 02 e8} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov bl, 2; call 0x4253a9;  
		$rule2 = {91 48 c1 e0 08 ac e8} 
		// xchg eax, ecx; dec eax; shl eax, 8; lodsb al, byte ptr [esi]; call 0x4253b3;  
		$rule3 = {ac d1 e8 74} 
		// lodsb al, byte ptr [esi]; shr eax, 1; je 0x4253c5;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Packman_1
{
meta:
		packer="Packman"
		generator="PackGenome"
		index="1"
	strings:
		$rule0 = {a4 b3 02 e8} 
		// movsb byte ptr es:[edi], byte ptr [esi]; mov bl, 2; call 0x4253a9;  
		$rule1 = {41 41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x425337;  
		$rule2 = {95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x425337;  
		$rule3 = {41 95 8b c5 b3 01 56 8b f7 2b f0 f3 a4 5e eb} 
		// inc ecx; xchg eax, ebp; mov eax, ebp; mov bl, 1; push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x425337;  
		$rule4 = {56 8b f7 2b f0 f3 a4 5e eb} 
		// push esi; mov esi, edi; sub esi, eax; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; jmp 0x425337;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_Packman_2
{
meta:
		packer="Packman"
		generator="PackGenome"
		index="2"
	strings:
		$rule0 = {57 46 8b 3c 2e 2b fb 2b fe 89 3c 2e 83 f8 03 77} 
		// push edi; inc esi; mov edi, dword ptr [esi + ebp]; sub edi, ebx; sub edi, esi; mov dword ptr [esi + ebp], edi; cmp eax, 3; ja 0x498f06;  
		$rule1 = {83 c6 03 8a 0c 2e d0 e9 0f 93 c5 fe cd 88 2c 2e 5f 46 3b f7 7c} 
		// add esi, 3; mov cl, byte ptr [esi + ebp]; shr cl, 1; setae ch; dec ch; mov byte ptr [esi + ebp], ch; pop edi; inc esi; cmp esi, edi; jl 0x498eb4;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 1 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// jdpack
rule packer_jdpack_0
{
meta:
		packer="jdpack"
		generator="PackGenome"
		index="0"
	strings:
		$rule0 = {8a 85 60 34 40 00 8a 1e 32 c3 88 06 88 9d 60 34 40 00 46 } 
		// mov al, byte ptr [ebp + 0x403460]; mov bl, byte ptr [esi]; xor al, bl; mov byte ptr [esi], al; mov byte ptr [ebp + 0x403460], bl; inc esi; loop 0x418043;  
		$rule1 = {c7 85 69 34 40 00 01 00 00 00 b9 88 07 00 00 8d b5 18 2c 40 00 8a 85 60 34 40 00 8a 1e 32 c3 88 06 88 9d 60 34 40 00 46 } 
		// mov dword ptr [ebp + 0x403469], 1; mov ecx, 0x788; lea esi, [ebp + 0x402c18]; mov al, byte ptr [ebp + 0x403460]; mov bl, byte ptr [esi]; xor al, bl; mov byte ptr [esi], al; mov byte ptr [ebp + 0x403460], bl; inc esi; loop 0x418043;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 1 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// exe32pack
rule packer_exe32pack_0
{
meta:
		packer="exe32pack"
		generator="PackGenome"
		index="0"
	strings:
		$rule0 = {8a 1e 46 88 1f 47 d1 ea 48 90 3b ce 75} 
		// mov bl, byte ptr [esi]; inc esi; mov byte ptr [edi], bl; inc edi; shr edx, 1; dec eax; nop ; cmp ecx, esi; jne 0x4161d8;  
		$rule1 = {8b f7 41 2b f3 f3 a4 8b 75 fc 8b 4d f8 83 c6 02 eb} 
		// mov esi, edi; inc ecx; sub esi, ebx; rep movsb byte ptr es:[edi], byte ptr [esi]; mov esi, dword ptr [ebp - 4]; mov ecx, dword ptr [ebp - 8]; add esi, 2; jmp 0x416226;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 1 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// beroexepacker
rule packer_beroexepacker_0
{
meta:
		packer="beroexepacker"
		generator="PackGenome"
		index="0"
	strings:
		$rule0 = {89 45 f4 ba 00 08 00 00 2b 11 c1 ea 05 01 11 f8 9c 81 7d f4 00 00 00 01 73} 
		// mov dword ptr [ebp - 0xc], eax; mov edx, 0x800; sub edx, dword ptr [ecx]; shr edx, 5; add dword ptr [ecx], edx; clc ; pushfd ; cmp dword ptr [ebp - 0xc], 0x1000000; jae 0x426174;  
		$rule1 = {88 45 f8 aa ff 45 fc c3} 
		// mov byte ptr [ebp - 8], al; stosb byte ptr es:[edi], al; inc dword ptr [ebp - 4]; ret ;  
		$rule2 = {29 45 f4 29 45 f0 8b 11 c1 ea 05 29 11 f9 eb} 
		// sub dword ptr [ebp - 0xc], eax; sub dword ptr [ebp - 0x10], eax; mov edx, dword ptr [ecx]; shr edx, 5; sub dword ptr [ecx], edx; stc ; jmp 0x42615e;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 2 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


// neolite
rule packer_neolite_0
{
meta:
		packer="neolite"
		generator="PackGenome"
		index="0"
	strings:
		$rule0 = {66 8b 06 89 5d 00 83 c6 02 81 c3 02 00 02 00 66 89 07 83 c7 02 83 c5 04 83 e9 02 75} 
		// mov ax, word ptr [esi]; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule1 = {2b 5c 24 28 a4 66 89 5d 00 83 c5 02 66 a5 5e 8b d8 3b 3c 24 0f87} 
		// sub ebx, dword ptr [esp + 0x28]; movsb byte ptr es:[edi], byte ptr [esi]; mov word ptr [ebp], bx; add ebp, 2; movsw word ptr es:[edi], word ptr [esi]; pop esi; mov ebx, eax; cmp edi, dword ptr [esp];  
		$rule2 = {90 90 90 90 a4 66 89 5d 00 43 83 c5 02 49 8b c3 43 c1 e3 10 66 8b d8 66 8b 06 89 5d 00 83 c6 02 81 c3 02 00 02 00 66 89 07 83 c7 02 83 c5 04 83 e9 02 75} 
		// nop ; nop ; nop ; nop ; movsb byte ptr es:[edi], byte ptr [esi]; mov word ptr [ebp], bx; inc ebx; add ebp, 2; dec ecx; mov eax, ebx; inc ebx; shl ebx, 0x10; mov bx, ax; mov ax, word ptr [esi]; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule3 = {8b c3 43 c1 e3 10 66 8b d8 66 8b 06 89 5d 00 83 c6 02 81 c3 02 00 02 00 66 89 07 83 c7 02 83 c5 04 83 e9 02 75} 
		// mov eax, ebx; inc ebx; shl ebx, 0x10; mov bx, ax; mov ax, word ptr [esi]; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule4 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule5 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule6 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule7 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule8 = {d1 e9 f3 66 a5 13 c9 f3 a4 5e 8b d8 0f87} 
		// shr ecx, 1; rep movsw word ptr es:[edi], word ptr [esi]; adc ecx, ecx; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		
	condition:
		pe.is_32bit() and (6 of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_neolite_1
{
meta:
		packer="neolite"
		generator="PackGenome"
		index="1"
	strings:
		$rule0 = {66 8b 06 89 5d 00 83 c6 02 81 c3 02 00 02 00 66 89 07 83 c7 02 83 c5 04 83 e9 02 75} 
		// mov ax, word ptr [esi]; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule1 = {2b 5c 24 28 a4 66 89 5d 00 83 c5 02 66 a5 5e 8b d8 3b 3c 24 0f87} 
		// sub ebx, dword ptr [esp + 0x28]; movsb byte ptr es:[edi], byte ptr [esi]; mov word ptr [ebp], bx; add ebp, 2; movsw word ptr es:[edi], word ptr [esi]; pop esi; mov ebx, eax; cmp edi, dword ptr [esp];  
		$rule2 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule3 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule4 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule5 = {83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 81 c3 02 00 02 00 [0-4] 07 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 83 c5 ?? 75} 
		// add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4;  
		$rule6 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule7 = {43 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 [0-2] [0-4] [0-2] [0-6] [0-6] [0-6] 89 5d 00 83 c6 02 81 c3 02 00 02 00 [0-4] 07 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 83 (c0|c1|c2|c3|c4|c5|c6|c7) 04 83 e9 02 75} 
		// inc ebx; add ebp, 2; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule8 = {d1 e9 f3 66 a5 13 c9 f3 a4 5e 8b d8 0f87} 
		// shr ecx, 1; rep movsw word ptr es:[edi], word ptr [esi]; adc ecx, ecx; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule9 = {d1 e9 f3 66 a5 13 c9 f3 a4 5e 8b d8 0f87} 
		// shr ecx, 1; rep movsw word ptr es:[edi], word ptr [esi]; adc ecx, ecx; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax;  
		$rule10 = {43 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 [0-2] [0-4] [0-2] [0-6] [0-6] [0-6] 89 5d 00 83 c6 02 81 c3 02 00 02 00 [0-4] 07 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 83 (c0|c1|c2|c3|c4|c5|c6|c7) 04 83 e9 02 75} 
		// inc ebx; add ebp, 2; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2;  
		$rule11 = {83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 81 c3 02 00 02 00 [0-4] 07 83 (c0|c1|c2|c3|c4|c5|c6|c7) 02 83 c5 ?? 75} 
		// add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4;  
		
	condition:
		pe.is_32bit() and (8 of them) and (pe.overlay.offset == 0 or for 5 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_neolite_2
{
meta:
		packer="neolite"
		generator="PackGenome"
		index="2"
	strings:
		$rule0 = {8b 4c 24 04 f7 c1 03 00 00 00 74} 
		// mov ecx, dword ptr [esp + 4]; test ecx, 3; je 0x4110f0;  
		$rule1 = {8a 01 83 c1 01 84 c0 74} 
		// mov al, byte ptr [ecx]; add ecx, 1; test al, al; je 0x411123;  
		$rule2 = {59 85 c0 (74|0f84)} 
		// pop ecx; test eax, eax; je 0x41be45;  
		$rule3 = {50 ff 75 08 e8} 
		// push eax; push dword ptr [ebp + 8]; call 0x41eae4;  
		$rule4 = {59 59 b9 ff ff 00 00 66 3b c1 75} 
		// pop ecx; pop ecx; mov ecx, 0xffff; cmp ax, cx; jne 0x4156d1;  
		$rule5 = {8b 4d fc 5f 5e 33 cd 5b e8} 
		// mov ecx, dword ptr [ebp - 4]; pop edi; pop esi; xor ecx, ebp; pop ebx; call 0x410135;  
		$rule6 = {47 56 e8} 
		// inc edi; push esi; call 0x4110c0;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 4 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


rule packer_neolite_3
{
meta:
		packer="neolite"
		generator="PackGenome"
		index="3"
	strings:
		$rule0 = {66 8b 06 89 5d 00 83 c6 02 81 c3 02 00 02 00 66 89 07 83 c7 02 83 c5 04 83 e9 02 75} 
		// mov ax, word ptr [esi]; mov dword ptr [ebp], ebx; add esi, 2; add ebx, 0x20002; mov word ptr [edi], ax; add edi, 2; add ebp, 4; sub ecx, 2; jne 0x4de577;  
		$rule1 = {2b 5c 24 28 a4 66 89 5d 00 83 c5 02 66 a5 5e 8b d8 3b 3c 24 0f87} 
		// sub ebx, dword ptr [esp + 0x28]; movsb byte ptr es:[edi], byte ptr [esi]; mov word ptr [ebp], bx; add ebp, 2; movsw word ptr es:[edi], word ptr [esi]; pop esi; mov ebx, eax; cmp edi, dword ptr [esp]; ja 0x4de8c2;  
		$rule2 = {8b df 8a 0e 2b 5c 24 24 46 66 89 5d 00 83 c5 02 88 0f 47 33 c9 8b d8 3b 3c 24 0f87} 
		// mov ebx, edi; mov cl, byte ptr [esi]; sub ebx, dword ptr [esp + 0x24]; inc esi; mov word ptr [ebp], bx; add ebp, 2; mov byte ptr [edi], cl; inc edi; xor ecx, ecx; mov ebx, eax; cmp edi, dword ptr [esp]; ja 0x4de8c2;  
		$rule3 = {66 89 5d 00 83 c5 02 f3 a4 5e 8b d8 3b 3c 24 0f87} 
		// mov word ptr [ebp], bx; add ebp, 2; rep movsb byte ptr es:[edi], byte ptr [esi]; pop esi; mov ebx, eax; cmp edi, dword ptr [esp]; ja 0x4de8c2;  
		$rule4 = {90 90 90 90 66 a5 a4 73} 
		// nop ; nop ; nop ; nop ; movsw word ptr es:[edi], word ptr [esi]; movsb byte ptr es:[edi], byte ptr [esi]; jae 0x4de472;  
		
	condition:
		pe.is_32bit() and (all of them) and (pe.overlay.offset == 0 or for 3 of ($*) : (@ < pe.overlay.offset)) and (not dotnet.is_dotnet)
}


