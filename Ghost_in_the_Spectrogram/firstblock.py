import subprocess
p="ECHO-7-LANTERN"
ciphers="""-aes-128-cbc -aes-192-cbc -aes-256-cbc -aes-128-ecb -aes-256-ecb
-aes-128-cfb -aes-256-cfb -aes-128-ofb -aes-256-ofb -aes-128-ctr -aes-256-ctr
-des-cbc -des-ede3 -des-ede3-cbc -bf-cbc -cast5-cbc -camellia-256-cbc
-aria-256-cbc -seed-cbc -rc2-cbc -rc4 -chacha20 -sm4-cbc""".split()
variants=[[], ['-pbkdf2'], ['-pbkdf2','-iter','10000'], ['-pbkdf2','-iter','100000'], ['-pbkdf2','-iter','1000000']]
res=[]
for c in ciphers:
  for v in variants:
    for md in ['sha256','md5','sha1']:
      cmd=['openssl','enc','-d',c,'-md',md]+v+['-in','openssl.bin','-pass','pass:'+p]
      r=subprocess.run(cmd,capture_output=True)
      out=r.stdout
      if len(out)>=16:
        head=out[:48]
        pr=sum(1 for x in head if 32<=x<127)/len(head)
        # also check for known magic
        bonus=0
        if b'HackCTF' in out[:1000] or b'CTF{' in out[:1000]: bonus=10
        res.append((pr+bonus, pr, c, ' '.join(v), md, out[:48]))
res.sort(reverse=True)
for x in res[:12]:
    print(f"{x[0]:.2f} pr={x[1]:.2f} {x[2]:18s} {' '.join(x[3]) or '':0s} kdf={' '.join(x[3].split()) or 'legacy'} md={x[4]}")
    print("   ", x[5])
