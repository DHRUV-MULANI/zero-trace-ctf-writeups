import numpy as np, wave, sys

w = wave.open('deleted_file','rb')
n=w.getnframes(); sr=w.getframerate(); ch=w.getnchannels()
raw=np.frombuffer(w.readframes(n),dtype=np.int16).reshape(-1,ch)
left=raw[:,0].astype(np.float64)

start=float(sys.argv[1]); end=float(sys.argv[2])
lo=float(sys.argv[3]); hi=float(sys.argv[4])
nfft=int(sys.argv[5]); hop=int(sys.argv[6])
rows=int(sys.argv[7]); cols=int(sys.argv[8])
reverse = len(sys.argv)>9 and sys.argv[9]=='rev'

x=left[int(start*sr):int(end*sr)].copy()
if reverse: x=x[::-1]
x=x-x.mean()

win=np.hanning(nfft)
fr=[]
for i in range(0,len(x)-nfft,hop):
    fr.append(np.abs(np.fft.rfft(x[i:i+nfft]*win)))
S=np.array(fr).T
freqs=np.fft.rfftfreq(nfft,1/sr)
idx=np.where((freqs>=lo)&(freqs<=hi))[0]
S=S[idx,:]
S=20*np.log10(S+1e-9)

# resample to rows x cols grid (bilinear via PIL)
from PIL import Image
img=Image.fromarray(S.astype(np.float32),mode='F')
img=img.resize((cols,rows),Image.BILINEAR)
G=np.array(img)

# denoise: subtract per-frequency-row baseline (median over time)
base=np.median(G,axis=1,keepdims=True)
G=G-base
# normalize
lo_p=np.percentile(G,2); hi_p=np.percentile(G,99)
N=np.clip((G-lo_p)/(hi_p-lo_p+1e-9),0,1)

chars=" .:-=+*#%@"
for r in range(rows-1,-1,-1):
    line=''.join(chars[min(len(chars)-1,int(v*(len(chars)-1)))] for v in N[r])
    print(f"{r:2d}|{line}")
