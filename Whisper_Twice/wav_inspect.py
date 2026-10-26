import wave, struct, numpy as np, sys

def load(path):
    w=wave.open(path,'rb')
    print(path, 'ch',w.getnchannels(),'width',w.getsampwidth(),'rate',w.getframerate(),'frames',w.getnframes())
    raw=w.readframes(w.getnframes())
    a=np.frombuffer(raw,dtype='<i2').reshape(-1,2)
    return a

def bits_from(arr,stride=7,start=1000,which='lsb'):
    s=arr[start::stride]
    if which=='lsb': return (s & 1).astype(np.uint8)
    if which=='sign': return ((s<0)).astype(np.uint8)
    if which=='parity': return (np.bitwise_xor.reduce(s.astype(np.uint16)&0xffff,axis=1) if False else (np.unpackbits(s.view(np.uint8)).reshape(-1,16).sum(1)&1)).astype(np.uint8)

def bits_to_bytes(bits):
    n=len(bits)//8*8
    return bytes(int(''.join(map(str,bits[i:i+8])),2) for i in range(0,n,8))

for path in ['vault_14454_5.wav','vault_591475_7.wav']:
    a=load(path)
    for which in ['lsb','sign']:
        bits=bits_from(a[:,1],7,1000,which)
        by=bits_to_bytes(bits)
        print(' ',which,'nbits',len(bits),'head bytes',by[:32].hex(),repr(by[:32]))
        for pat in [b'FNL!',b'FNL',b'flag',b'HackCTF',b'PK']:
            idx=by.find(pat)
            if idx>=0: print('   found',pat,'at byte',idx)
    # left channel stats
    l=a[:,0]
    print(' left min/max',l.min(),l.max(),'unique',len(np.unique(l)),'first20',l[:20])
    print(' right first20',a[:20,1])
    # differences
    print(' left diff unique head',np.unique(np.diff(l))[:20])
