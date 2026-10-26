import wave, numpy as np

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

chars=' .:-=+*#%@'
def ascii_img(arr,W=100,H=40):
    # arr 1d length, split rows after reversing maybe
    n=len(arr); rows=np.array_split(arr,H)
    out=[]
    for r in rows:
        # downsample to W by mean abs
        idx=np.linspace(0,len(r),W+1).astype(int)
        vals=np.array([r[idx[i]:idx[i+1]].mean() for i in range(W)])
        v=np.abs(vals)
        if v.max()==0: vv=np.zeros(W)
        else: vv=(v/v.max()*9).astype(int)
        out.append(''.join(chars[x] for x in vv))
    return '\n'.join(out)

for path,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(path); l=a[:,0].astype(np.float64)
    for rev in [False,True]:
        x=l[::-1] if rev else l
        print('='*100)
        print(path,'rev' if rev else 'fwd')
        print(ascii_img(x,120,45))
