mySth = [0x45, 0xd, 0x50, 0x1c, 0x5d, 0xa, 0x46, 0x2d,
                    0x5e, 0x1f, 0x44, 0x17, 0x54, 0x2d, 0x6, 0x11,
                    0x54, 0x6, 0x34, 0x7, 0x41, 0xe, 0x52, 0x2d,
                    0x19, 0x16, 0x3e, 0x1, 0x6, 0x5a, 0x1c, 0x56]
sth = [0x70 ,0x65,0x61 ,0x72 ,0x6C ,0x64 ,0x61 ,0x72 ,0x6B ,0x6B] #"pearldarrk"

for i in range(len(mySth)):
    mySth[i]=mySth[i]^sth[i%10]
    print(chr(mySth[i]),end="")

