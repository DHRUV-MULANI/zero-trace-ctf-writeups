import wave, numpy as np
from PIL import Image

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

chars=' .:-=+*#%@'
def render(mat,W=120,H=45,log=True):
    # mat shape (freqbins, time)
    m=np.abs(mat)
    if log: m=np.log1p(m)
    # downsample to W x H
    from PIL import Image as I
    im=I.fromarray(m)
    im=im.resize((W,H))
    m=np.array(im)
    m=(m-m.min())/(m.max()-m.min()+1e-9)
    out=[]
    for row in m[::-1]:  # low freq bottom
        out.append(''.join(chars[int(v*9)] for v in row))
    return '\n'.join(out)

for path,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(path)
    for chname,ch in [('L',a[:,0]),('R',a[:,1])]:
        x=ch.astype(np.float64)
        N=1024; hop=128
        frames=[]
        win=np.hanning(N)
        for i in range(0,len(x)-N,hop):
            frames.append(np.abs(np.fft.rfft(x[i:i+N]*win)))
        mat=np.array(frames).T
        print('='*140)
        print(path,chname,'spec shape',mat.shape)
        print(render(mat,120,45))
