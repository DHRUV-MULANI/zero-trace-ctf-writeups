import subprocess, os, itertools, math
blob=open('openssl.bin','rb').read()
ciphers="""-aes-128-ctr -aes-192-ctr -aes-256-ctr -aes-128-cfb -aes-256-cfb -aes-128-ofb -aes-256-ofb
-chacha20 -rc4 -rc4-40 -des-cfb -des-ofb -bf-cfb -bf-ofb -cast5-cfb -cast5-ofb
-aes-128-cbc -aes-192-cbc -aes-256-cbc -aes-128-ecb -aes-256-ecb""".split()
passes=["ECHO-7-LANTERN"]
mds=["sha256","md5","sha1"]
def score(b):
    if not b: return -1
    printable=sum(1 for x in b[:4000] if 32<=x<127 or x in (9,10,13))
    s=printable/min(len(b),4000)
    if b'HackCTF' in b or b'hackctf' in b.lower(): s+=10
    if b'CTF{' in b: s+=5
    if b'flag' in b.lower(): s+=3
    return s
best=[]
for c in ciphers:
    for p in passes:
        for md in mds:
            try:
                r=subprocess.run(['openssl','enc','-d',c,'-md',md,'-in','openssl.bin','-pass','pass:'+p],capture_output=True,timeout=20)
                s=score(r.stdout)
                if r.returncode==0 or s>0.7:
                    best.append((s,c,p,md,r.returncode,r.stdout[:200]))
            except Exception as e:
                pass
best.sort(reverse=True)
for s,c,p,md,rc,head in best[:15]:
    print(f"{s:.3f} rc={rc} {c} {md} {p!r}")
    print("   ",head)
