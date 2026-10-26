import wave, numpy as np, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from PIL import Image

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

for path,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(path); l=a[:,0].astype(np.float64)
    for rev in [False,True]:
        x=l[::-1] if rev else l
        for nfft,hop in [(1024,64),(512,32),(2048,128)]:
            plt.figure(figsize=(16,8))
            plt.specgram(x,NFFT=nfft,Fs=22050,noverlap=nfft-hop,cmap='inferno')
            plt.axis('off')
            fn=f'spec_{tag}_{"rev" if rev else "fwd"}_{nfft}_{hop}.png'
            plt.savefig(fn,bbox_inches='tight',pad_inches=0,dpi=150)
            plt.close()
            print(fn)
