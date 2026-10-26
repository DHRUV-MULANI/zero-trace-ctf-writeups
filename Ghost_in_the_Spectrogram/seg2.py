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
S=20*np.log10(np.array(fr).T+1e-9)
freqs=np.fft.rfftfreq(nfft,1/sr); idx=np.where((freqs>=lo)&(freqs<=hi))[0]
S=S[idx,:]
W=720; H=90
G=np.array(Image.fromarray(S.astype(np.float32),mode='F').resize((W,H),Image.BILINEAR))
base=np.median(G,axis=1,keepdims=True); D=G-base
# text rows 15..73
b=8
mask=(D> b).astype(np.uint8)
rowsum=mask.sum(axis=1)
colsum=mask.sum(axis=0)
print("rows with content:")
for i in range(H):
    print(f"{i:2d} {rowsum[i]:4d} " + "#"*rowsum[i])
np.save('mask.npy',mask); np.save('D.npy',D)
