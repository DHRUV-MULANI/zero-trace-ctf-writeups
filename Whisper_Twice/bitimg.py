import wave, numpy as np
from PIL import Image

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

def pack(bits,msb=True,dims=(400,600),inv=False):
    n=dims[0]*dims[1]
    b=bits[:n]
    if msb:
        # pack bits as rows MSB first
        by=np.packbits(b.astype(np.uint8),bitorder='big')
    else:
        by=np.packbits(b.astype(np.uint8),bitorder='little')
    return by

for path,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(path)
    for ch,chname in [(a[:,0],'L'),(a[:,1],'R')]:
        for bitname,bits in [('lsb',(ch&1)),('sign',(ch<0).astype(np.int16))]:
            bits=bits.astype(np.uint8)
            for rev in [False,True]:
                bb=bits[::-1] if rev else bits
                for (W,H) in [(400,600),(600,400),(480,500),(500,480),(300,800),(800,300),(240,1000),(1000,240),(200,1200),(1200,200)]:
                    if W*H>len(bb): continue
                    for order in ['big','little']:
                        by=np.packbits(bb[:W*H],bitorder=order)
                        # unpack to 2d via np.unpackbits
                        arr=np.unpackbits(by,bitorder=order)[:W*H].reshape(H,W)*255
                        fn=f'bitimg_{tag}_{chname}_{bitname}_{"rev" if rev else "fwd"}_{W}x{H}_{order}.png'
                        Image.fromarray(arr.astype(np.uint8)).save(fn)
print('done')
