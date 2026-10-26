import wave, numpy as np, zlib, glob, os
from PIL import Image

def load(p):
    w=wave.open(p,'rb'); return np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').reshape(-1,2)

def save_variants(vals,tag):
    res=[]
    for W,H in [(400,600),(600,400),(480,500),(500,480),(300,800),(800,300),(240,1000),(1000,240),(200,1200),(1200,200),(100,2400),(2400,100),(200,1200),(150,1600),(1600,150)]:
        if W*H>len(vals): continue
        a=vals[:W*H]
        for name,arr in [('fwd',a),('rev',a[::-1])]:
            img=arr.reshape(H,W)
            # normalize to 0-255 using percentiles
            lo,hi=np.percentile(img,[1,99.5])
            im=np.clip((img-lo)/(hi-lo+1e-9),0,1)
            fn=f'envimg_{tag}_{name}_{W}x{H}.png'
            Image.fromarray((im*255).astype(np.uint8)).save(fn)
            # threshold via otsu-ish mean
            th=im.mean()
            bw=(im>th).astype(np.uint8)*255
            Image.fromarray(bw).save(f'envbw_{tag}_{name}_{W}x{H}.png')
            # score: zlib of 8-bit image and of bw
            score=len(zlib.compress(im.astype(np.uint8).tobytes(),9))
            bscore=len(zlib.compress((im>th).astype(np.uint8).tobytes(),9))
            res.append((score,bscore,fn))
    return res

for p,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(p); l=a[:,0].astype(float)
    vals=np.abs(l)
    res=save_variants(vals,tag)
    print('='*60,tag)
    for s,b,f in sorted(res)[:15]: print(s,b,f)
