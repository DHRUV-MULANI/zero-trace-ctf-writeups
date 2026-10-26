import wave, numpy as np
from PIL import Image

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

def spec_img(x,outbase,N=2048,hop=32,log=True,clip=99.5):
    win=np.hanning(N)
    frames=[]
    for i in range(0,len(x)-N,hop):
        frames.append(np.abs(np.fft.rfft(x[i:i+N]*win)))
    mat=np.array(frames).T  # freq x time
    m=np.log1p(mat) if log else mat
    # crop to freq range 0..8000
    maxb=int(8000/ (22050/N))
    m=m[:maxb]
    lo=np.percentile(m,1); hi=np.percentile(m,clip)
    m=np.clip((m-lo)/(hi-lo+1e-9),0,1)
    im=(m[::-1]*255).astype(np.uint8)  # low freq bottom
    Image.fromarray(im).save(outbase+'_full.png')
    # upscale
    scale=3
    Image.fromarray(im).resize((im.shape[1]*scale,im.shape[0]*scale),Image.LANCZOS).save(outbase+'_big.png')
    return im

for path,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(path); l=a[:,0].astype(float)
    # focus burst region (last 40%) and full
    seg=l[int(len(l)*0.55):]
    for rev in [False,True]:
        x=l[::-1] if rev else l
        s=x[int(len(x)*0.55):] if not rev else x[:int(len(x)*0.45)]
        base=f'hspec_{tag}_{"rev" if rev else "fwd"}'
        spec_img(s,base,N=2048,hop=32)
        print(base)
        # also full
        spec_img(x,base+'_fullwav',N=2048,hop=64)