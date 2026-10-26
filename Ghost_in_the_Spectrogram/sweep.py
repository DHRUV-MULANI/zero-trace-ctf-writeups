import subprocess
base="ECHO-7-LANTERN"
cands=set()
for s in [base, base.lower(), base.upper(), base.replace('-',''), base.replace('-','_'),
          base.replace('-',' '), base.replace('7','T'), base.lower().replace('-','_'),
          base.lower().replace('-',''), "ECHO7LANTERN", "echo7lantern",
          "HackCTF{"+base+"}", "HackCTF{"+base.lower()+"}",
          base.replace('-', '')+"7", "LANTERN", "lantern", "ECHO", "echo",
          "ECHO-7", "echo-7", "Ghost", "ghost", "GHOST", "spectrogram", "SPECTROGRAM"]:
    cands.add(s)
ciphers="""-aes-128-cbc -aes-192-cbc -aes-256-cbc -aes-128-ecb -aes-256-ecb
-aes-128-cfb -aes-256-cfb -aes-128-ofb -aes-256-ofb -aes-128-ctr -aes-256-ctr
-des-cbc -des-ede3 -des-ede3-cbc -des-ede-cbc -bf-cbc -cast5-cbc -camellia-128-cbc
-camellia-192-cbc -camellia-256-cbc -seed-cbc -aria-128-cbc -aria-256-cbc
-rc2-cbc -rc4 -chacha20""".split()
mds=["sha256","md5","sha1"]
hits=[]
for p in sorted(cands):
    for c in ciphers:
        for md in mds:
            r=subprocess.run(['openssl','enc','-d',c,'-md',md,'-in','openssl.bin','-pass','pass:'+p],capture_output=True)
            if r.returncode==0 and r.stdout:
                pr=sum(1 for x in r.stdout[:3000] if 32<=x<127 or x in (9,10,13))/max(1,min(len(r.stdout),3000))
                hits.append((pr,p,c,md,r.stdout[:100]))
hits.sort(reverse=True)
for h in hits[:15]: print(h)
print("total valid-padding hits:",len(hits))
