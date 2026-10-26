import struct, zlib, hashlib, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

beacons={
 '10.13.37.5':bytes.fromhex('ce0513ae8d021d81fb72b52b827c444d'),
 '10.13.37.6':bytes.fromhex('ee2afaf24ddd37989f4a630e0ed20734'),
 '10.13.37.7':bytes.fromhex('7640a9d379f2042e2ce88c50b1c25c1b'),
}

def find_records(data, label):
    print('='*70); print('scan',label,len(data))
    i=0; recs=[]
    while True:
        i=data.find(b'VLT1',i)
        if i<0: break
        off=i
        try:
            salt=data[i+4:i+20]
            ln=struct.unpack('>I',data[i+20:i+24])[0]
            ct=data[i+24:i+24+ln]
            crc=data[i+24+ln:i+24+ln+4]
            if len(salt)==16 and 0<ln<5_000_000 and len(ct)==ln and len(crc)==4:
                calc=zlib.crc32(salt+ct)&0xffffffff
                got=struct.unpack('>I',crc)[0]
                ok=(calc==got)
                if ok or True:
                    print(f'offset {off} len {ln} crc {ok} salt {salt.hex()} ct_head {ct[:8].hex()} crc {got:08x} calc {calc:08x}')
                    if ok: recs.append((off,salt,ct))
            else:
                print(f'offset {off} parse truncated ln={ln}')
        except Exception as e:
            print('offset',off,'err',e)
        i+=4
    return recs

def try_decrypt(recs):
    for off,salt,ct in recs:
        for name,b in beacons.items():
            key=hashlib.sha256(b+salt).digest()
            try:
                dec=Cipher(algorithms.AES(key),modes.CBC(salt)).decryptor()
                pt=dec.update(ct)+dec.finalize()
                # unpad
                p=pt[-1]
                pt2=pt[:-p] if 1<=p<=16 and all(x==p for x in pt[-p:]) else pt
                try:
                    un=zlib.decompress(pt2)
                    print('SUCCESS',name,'offset',off,'key',key.hex(),'inner len',len(un),'head',un[:20])
                    open(f'recovered_{name.replace(".","_")}_{off}.bin','wb').write(un)
                except Exception:
                    if name==list(beacons)[0]:
                        print('decrypt ok? offset',off,'name',name,'pt head',pt2[:16].hex(),'(no zlib)')
            except Exception as e:
                pass

data=open('deleted_vault.bin','rb').read()
recs=find_records(data,'deleted_vault.bin')
print('valid records',len(recs))
try_decrypt(recs)
