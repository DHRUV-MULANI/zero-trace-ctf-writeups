import numpy as np, wave, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

w = wave.open('deleted_file','rb')
n = w.getnframes(); sr = w.getframerate(); ch = w.getnchannels()
raw = np.frombuffer(w.readframes(n), dtype=np.int16).reshape(-1, ch)
left = raw[:,0].astype(np.float64)
# use only 10.0 to 22.5 s
s0 = int(10.0*sr); s1 = int(22.5*sr)
x = left[s0:s1]
x = x - x.mean()

for nfft, hop, tag in [(1024,128,'a'), (2048,128,'b'), (512,64,'c')]:
    win = np.hanning(nfft)
    frames = []
    for i in range(0, len(x)-nfft, hop):
        seg = x[i:i+nfft]*win
        S = np.abs(np.fft.rfft(seg))
        frames.append(S)
    S = np.array(frames).T  # freq x time
    freqs = np.fft.rfftfreq(nfft, 1/sr)
    lo, hi = 4000, 7000
    idx = (freqs>=lo)&(freqs<=hi)
    S = S[idx,:]
    S = 20*np.log10(S+1e-9)
    # normalize
    S = np.clip((S - np.percentile(S,20)) / (np.percentile(S,99.5)-np.percentile(S,20)),0,1)
    plt.figure(figsize=(28, 10))
    plt.imshow(S, aspect='auto', origin='lower', cmap='inferno',
               extent=[10.0, 10.0+len(x)/sr, lo, hi])
    plt.xlabel('time (s)'); plt.ylabel('freq (Hz)')
    plt.title(f'nfft={nfft} hop={hop}')
    plt.tight_layout()
    plt.savefig(f'view_{tag}.png', dpi=100)
    plt.close()
    print(tag, S.shape)
