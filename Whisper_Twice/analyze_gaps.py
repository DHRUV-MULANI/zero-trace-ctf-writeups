import subprocess, statistics, collections

pcap='extract/op/capture.pcap'
hosts={
 '10.13.37.5':'update.cdn-sync.net',
 '10.13.37.6':'update.cdn-sync.net',
 '10.13.37.7':'telemetry.cdn-sync.net',
}
for ip,q in hosts.items():
    out=subprocess.check_output(['tshark','-r',pcap,'-Y',f'dns && ip.src=={ip} && dns.qry.name=="{q}"','-T','fields','-e','frame.number','-e','frame.time_epoch','-e','dns.id','-e','udp.srcport'],text=True)
    rows=[]
    for line in out.strip().splitlines():
        p=line.split('\t')
        if len(p)>=4:
            rows.append((int(p[0]),float(p[1]),p[2],p[3]))
    ts=[r[1] for r in rows]
    gaps=[round(ts[i+1]-ts[i],4) for i in range(len(ts)-1)]
    c=collections.Counter(gaps)
    print('='*70)
    print(ip,q,'n=',len(rows),'unique ports',len(set(r[3] for r in rows)))
    print('first ts',ts[0],'last',ts[-1])
    print('gap top:',c.most_common(15))
    print('min/max/median',min(gaps),max(gaps),statistics.median(gaps))
    # count gaps > 1 (sync pauses)
    print('big gaps:',[(i,g) for i,g in enumerate(gaps) if g>0.8][:30])
    print('small gaps <0.05',sum(1 for g in gaps if g<0.05))
