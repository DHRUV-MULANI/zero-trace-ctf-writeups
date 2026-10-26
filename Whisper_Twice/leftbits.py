import wave, numpy as np, zlib
from PIL import Image

def load(p):
    w=wave.open(p,'rb'); return np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').reshape(-1,2)

def bits_of(samples, mode):
    if mode=='lsb': return (samples & 1).astype(np.uint8)
    if mode=='sign': return (samples<0).astype(np.uint8)
    if mode=='msb': return ((samples.astype(np.uint16)>>15)&1).astype(np.uint8)
    if mode=='parity': return (np.unpackbits(samples.astype(np.uint16).view(np.uint8)).reshape(-1,2).sum(1)&1).astype(np.uint8)

def tobytes(bits):
    return np.packbits(bits,bitorder='big').tobytes()

for p,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(p)
    print('='*70,tag)
    for chname,ch in [('L',a[:,0]),('R',a[:,1])]:
        for stride in [1,7]:
            for start in [0,1000]:
                s=ch[start::stride]
                for mode in ['lsb','sign','msb','parity']:
                    bits=bits_of(s,mode)
                    for rev in [False,True]:
                        b=bits[::-1] if rev else bits
                        by=tobytes(b)
                        sigs={'png':b'\x89PNG','jpg':b'\xff\xd8\xff','gif':b'GIF8','bmp':b'BM','pbm':b'P1','p6':b'P6','flag':b'HackCTF','hack':b'Hack','fnl':b'FNL!'}
                        found=[]
                        for name,sig in sigs.items():
                            i=by.find(sig)
                            if i>=0: found.append((name,i))
                        if found:
                            print(' ',chname,'stride',stride,'start',start,mode,'rev',rev,'nbytes',len(by),'sigs',found)
                            open(f'leftbits_{tag}_{chname}_{stride}_{start}_{mode}_{"rev" if rev else "fwd"}.bin','wb').write(by)
