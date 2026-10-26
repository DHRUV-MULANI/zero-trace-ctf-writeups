import numpy as np, wave
from PIL import Image

w=wave.open('deleted_file','rb'); n=w.getnframes(); sr=w.getframerate(); ch=w.getnchannels()
raw=np.frombuffer(w.readframes(n),dtype=np.int16).reshape(-1,ch)
left=raw[:,0].astype(np.float64)

start,end=10.5,22.5
lo,hi=4200,6900
nfft,hop=1024,128
x=left[int(start*sr):int(end*sr)].copy(); x=x-x.mean()
win=np.hanning(nfft)
fr=[np.abs(np.fft.rfft(x[i:i+nfft]*win)) for i in range(0,len(x)-nfft,hop)]
S=np.array(fr).T
freqs=np.fft.rfftfreq(nfft,1/sr)
idx=np.where((freqs>=lo)&(freqs<=hi))[0]
S=20*np.log10(S[idx,:]+1e-9)
img=Image.fromarray(S.astype(np.float32),mode='F').resize((720,90),Image.BILINEAR)
G=np.array(img)
base=np.median(G,axis=1,keepdims=True)
G=G-base
lo_p,hi_p=np.percentile(G,5),np.percentile(G,99.5)
N=np.clip((G-lo_p)/(hi_p-lo_p+1e-9),0,1)

# column profile over text rows (assume text in middle rows)
# find text rows: rows with high mean
rowmean=N.mean(axis=1)
print("rowmean:", " ".join(f"{i}:{v:.2f}" for i,v in enumerate(rowmean) if v>0.35))
