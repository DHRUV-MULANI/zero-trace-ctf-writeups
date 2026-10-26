import subprocess, struct, hashlib, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

pcap='extract/op/capture.pcap'
hosts={
 '10.13.37.5':('update.cdn-sync.net',None),
 '10.13.37.6':('update.cdn-sync.net',None),
 '10.13.37.7':('telemetry.cdn-sync.net',None),
}

def get_gaps(ip,q,cut=0.05):
    out=subprocess.check_output(['tshark','-r',pcap,'-Y',f'dns && ip.src=={ip} && dns.qry.name=="{q}"','-T','fields','-e','frame.number','-e','frame.time_epoch'],text=True)
    rows=[]
    for line in out.strip().splitlines():
        p=line.split('\t')
        if len(p)>=2: rows.append((int(p[0]),float(p[1])))
    rows.sort(key=lambda r:r[1])
    kept=[]
    for fn,ts in rows:
        if not kept or ts-kept[-1][1]>=cut:
            kept.append((fn,ts))
    gaps=[kept[i+1][1]-kept[i][1] for i in range(len(kept)-1)]
    return kept,gaps

def decode(gaps):
    # remove sync pauses >1.0 (should only be first)
    g=[x for x in gaps if x<=1.0]
    assert len(g)%2==0, (len(g),len(g)/2)
    # classify threshold midpoint
    vals=sorted(g)
    # print clusters
    # use threshold 0.36? Determine by kmeans-ish
    thr=(min(g)+max(g))/2
    # But there may be 2 clusters; use histogram gap
    bits=[]
    for i in range(0,len(g),2):
        a,b=g[i],g[i+1]
        sa=a<thr; sb=b<thr
        if sa and not sb: bits.append(1)  # short->long
        elif not sa and sb: bits.append(0) # long->short
        else:
            print('ambiguous pair',a,b)
            bits.append(None)
    by=bytearray()
    for i in range(0,len(bits),8):
        chunk=bits[i:i+8]
        v=0
        for bit in chunk:
            v=(v<<1)|(bit or 0)
        by.append(v)
    return thr,g,by,bits

for ip,(q,_) in hosts.items():
    kept,gaps=get_gaps(ip,q)
    thr,g,by,bits=decode(gaps)
    print('='*70)
    print(ip,q,'kept',len(kept),'gaps',len(gaps),'after pause',len(g),'thr',round(thr,4),'minmax',round(min(g),3),round(max(g),3))
    print('beacon hex:',by.hex())
    print('bits:', ''.join(str(b) if b is not None else '?' for b in bits))
    # also print raw sorted clustering
    import collections
    print('clusters:', collections.Counter(round(x,1) for x in g))
