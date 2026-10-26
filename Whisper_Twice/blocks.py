import wave,numpy as np
def load(p):
    w=wave.open(p,'rb'); return np.frombuffer(w.readframes(w.getnframes()),dtype='<i2').reshape(-1,2)
chars=' .:-=+*#%@'
def render(vals,H,W):
    img=vals.reshape(H,W)
    lo,hi=np.percentile(img,[2,98])
    im=np.clip((img-lo)/(hi-lo+1e-9),0,1)
    return '\n'.join(''.join(chars[int(v*9)] for v in row) for row in im)

for p,tag in [('vault_14454_5.wav','5'),('vault_591475_7.wav','7')]:
    a=load(p); l=a[:,0].astype(float)
    for period in [312.5,312.0]:
        nb=int(len(l)/period)
        vals=[]
        for i in range(nb):
            s=int(round(i*period)); e=int(round((i+1)*period))
            vals.append(np.sqrt((l[s:e]**2).mean()))
        vals=np.array(vals)
        print('#'*100)
        print(tag,'period',period,'blocks',len(vals))
        for H,W in [(24,32),(32,24),(16,48),(48,16),(12,64),(64,12),(8,96),(96,8),(6,128),(128,6),(4,192),(192,4),(3,256),(256,3),(2,384),(384,2),(1,768),(768,1)]:
            if H*W>len(vals): continue
            v=vals[:H*W]
            print('='*50,f'{W}x{H}')
            print(render(v,H,W))
            print('-- reversed --')
            print(render(v[::-1],H,W))
