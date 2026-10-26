import struct,zlib,hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
beacons={
 '.5':bytes.fromhex('ce0513ae8d021d81fb72b52b827c444d'),
 '.6':bytes.fromhex('ee2afaf24ddd37989f4a630e0ed20734'),
 '.7':bytes.fromhex('7640a9d379f2042e2ce88c50b1c25c1b'),
}
data=open('evidence.img','rb').read()
i=0
while True:
    i=data.find(b'VLT1',i)
    if i<0: break
    off=i
    salt=data[i+4:i+20]; ln=struct.unpack('>I',data[i+20:i+24])[0]
    ct=data[i+24:i+24+ln]; crc=data[i+24+ln:i+24+ln+4]
    calc=zlib.crc32(salt+ct)&0xffffffff
    got=struct.unpack('>I',crc)[0] if len(crc)==4 else None
    print('='*60)
    print('offset',off,'len',ln,'crc_ok',calc==got,'got',got,'calc',calc,'salt',salt.hex())
    if 0<ln<5_000_000 and len(ct)==ln:
        for name,b in beacons.items():
            key=hashlib.sha256(b+salt).digest()
            pt=Cipher(algorithms.AES(key),modes.CBC(salt)).decryptor().update(ct)
            pad=pt[-1]
            pt2=pt[:-pad] if 1<=pad<=16 and all(x==pad for x in pt[-pad:]) else None
            if pt2 is not None:
                try:
                    un=zlib.decompress(pt2)
                    print('  SUCCESS',name,len(un),un[:16])
                    open(f'img_{off}_{name[1:]}.wav','wb').write(un)
                except Exception:
                    pass
    i+=4
