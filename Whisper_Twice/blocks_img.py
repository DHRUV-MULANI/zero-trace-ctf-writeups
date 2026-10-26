import wave,numpy as np, subprocess, os
from PIL import Image

def load(p):
    w=wave.open(p,'rb'); return np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').reshape(-1,2)

def blocks(l,period=312.5):
    nb=int(len(l)/period)
    vals=[]
    for i in range(nb):
        s=int(round(i*period)); e=int(round((i+1)*period))
        vals.append(np.sqrt((l[s:e]**2).mean()))
    return np.array(vals)

for p,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    l=load(p)[:,0].astype(float)
    for period in [312.5,312.0]:
        vals=blocks(l,period)
        print('='*80); print(tag,period,len(vals),'minmax',vals.min(),vals.max())
        # threshold to find content
        base=np.median(vals)
        print('base',base,'high count',np.sum(vals>base*1.3))
        idx=np.where(vals>base*1.3)[0]
        print('content idx',idx.min() if len(idx) else None,idx.max() if len(idx) else None)
        for H,W in [(24,32),(32,24),(16,48),(48,16),(12,64),(64,12),(8,96),(96,8),(6,128),(128,6),(4,192),(192,4),(3,256),(256,3),(2,384),(384,2),(1,768),(768,1),(10,16),(16,10),(20,8),(8,20),(5,32),(32,5)]:
            if H*W>len(vals): continue
            v=vals[:H*W]
            img=v.reshape(H,W)
            lo,hi=np.percentile(img,[1,99])
            im=np.clip((img-lo)/(hi-lo+1e-9),0,1)
            for rev in [False,True]:
                arr=im[::-1] if rev else im
                fn=f'blk_{tag}_{period}_{W}x{H}_{"rev" if rev else "fwd"}.png'
                Image.fromarray((arr*255).astype(np.uint8)).resize((W*12,H*12),Image.LANCZOS).save(fn)
