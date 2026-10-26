import wave, numpy as np
from PIL import Image

def load(path):
    w=wave.open(path,'rb'); raw=w.readframes(w.getnframes())
    return np.frombuffer(raw,dtype='<i2').reshape(-1,2)

for path in ['vault_14454_5.wav','vault_591475_7.wav']:
    a=load(path)
    l=a[:,0].astype(np.float64)
    print('='*60,path,'len',len(l))
    # basic stats
    print('minmax',l.min(),l.max(),'mean',l.mean(),'std',l.std())
    # Save raw sample view as 16-bit image width 600, height 400
    for W in [400,600,500,480,320,800,300,240,1000]:
        H=len(l)//W
        if H*W!=len(l): continue
        # normalize as signed to 0-255
        img=((l.reshape(H,W)+32768)/65536*255).astype(np.uint8)
        Image.fromarray(img).save(f'left_{path.split("_")[1]}_raw_{W}x{H}.png')
        # normalized per image
        im2=l.reshape(H,W); im2=(im2-im2.min())/(im2.max()-im2.min()+1e-9)*255
        Image.fromarray(im2.astype(np.uint8)).save(f'left_{path.split("_")[1]}_norm_{W}x{H}.png')
        rev=img[::-1,::-1]
        Image.fromarray(rev).save(f'left_{path.split("_")[1]}_rev_{W}x{H}.png')
    # histogram coarse
    h,edges=np.histogram(l,bins=16)
    print('hist',list(zip(edges[:-1].round(0),h)))
