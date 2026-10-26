import wave,numpy as np, subprocess
from PIL import Image

def load(p):
    w=wave.open(p,'rb'); return np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').reshape(-1,2)

chars=' .:-=+*#%@'
def show(mat,W=160,H=45):
    im=Image.fromarray(mat.astype(np.float32)).resize((W,H),Image.LANCZOS)
    m=np.array(im); m-=m.min(); m/=(m.max()+1e-9)
    return '\n'.join(''.join(chars[int(v*9)] for v in row) for row in m[::-1])

for p,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    l=load(p)[:,0].astype(float)
    for N,hop in [(312,312),(313,313),(625,312),(1024,312)]:
        win=np.hanning(N)
        frames=[]
        for i in range(0,len(l)-N,hop):
            frames.append(np.abs(np.fft.rfft(l[i:i+N]*win)))
        mat=np.array(frames).T
        print('='*100)
        print(tag,'N',N,'hop',hop,'shape',mat.shape)
        # save full image
        m=np.log1p(mat)
        lo,hi=np.percentile(m,[1,99.5]); mm=np.clip((m-lo)/(hi-lo+1e-9),0,1)
        Image.fromarray((mm[::-1]*255).astype(np.uint8)).save(f'perblock_{tag}_{N}_{hop}_full.png')
        # content columns based on energy
        e=mat.mean(0); th=np.median(e)*1.3
        idx=np.where(e>th)[0]
        if len(idx):
            t0,t1=idx.min(),idx.max()
            print('content cols',t0,t1)
            sub=mm[:,max(0,t0-2):min(mat.shape[1],t1+3)]
            Image.fromarray((sub[::-1]*255).astype(np.uint8)).resize((sub.shape[1]*4,sub.shape[0]*4),Image.LANCZOS).save(f'perblock_{tag}_{N}_{hop}_content.png')
            print(show(np.log1p(mat[:,t0:t1]),160,40))
