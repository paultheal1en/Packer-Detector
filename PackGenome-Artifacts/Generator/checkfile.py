import pefile
pe = pefile.PE("C:/Users/Acer/Downloads/MyPinTool.dll")
machine = pe.FILE_HEADER.Machine

if machine == 0x14c:
    print("32-bit DLL")
elif machine == 0x8664:
    print("64-bit DLL")
else:
    print(f"Unknown architecture: {hex(machine)}")
