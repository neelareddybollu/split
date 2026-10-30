# gui7 — the scope, plus analysis

Everything `gui6` does, and two things it could not: it can tell you **what**
the signal is, not only where the energy sits.

```bash
bash build.sh
sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/split_scope7
./run.sh sfp1
```

No space after the comma in `setcap`, the capability is lost on every
rebuild, and do not start it with `sudo` — sudo discards the X authority
cookie and the window will not open.

---

## What's new

### Analyse — cyclic-prefix correlation and the resource grid

Pick a lane and a slot, press **Analyse**. The capture path copies that one
slot's raw IQ aside as it goes past, then the analysis runs **once**. It is
not a per-frame cost, so a 4096-point FFT never touches the capture rate.

**Cyclic-prefix correlation** is the cheaper half and, for timing questions,
the more useful one. Each OFDM symbol starts with a copy of its own tail, so
correlating the prefix against the body one symbol-period later gives two
things at once:

```
|r|       how well they match   -> confirms sample alignment, FFT size
                                   and numerology, all three at once
arg(r)    carrier frequency offset, because a frequency error rotates
          the signal by 2·pi·df·Tu across that interval

          df = −arg(r) / (2·pi·Tu),     Tu = nfft / sample_rate
```

At 4096 / 122.88 Msps, `Tu` is 33.33 µs, so a full 2π of phase is 30 kHz and
the measurement is unambiguous to about ±15 kHz.

**This measures the waveform itself.** It needs no pattern to lock onto, works
on a stream that never assembles a frame, and makes no assumption about what
`seq_id` means. That last point matters: the earlier drift figure came from
tracking burst position against `seq_id`, which is only valid if `seq_id` is a
frame address. This is not.

**The resource grid** is a 14 × N_PRB heat map of power in dB — symbol against
resource block. That is what turns *"slot 10 is busy"* into *"PDCCH in symbol 0
across 24 PRB, PDSCH over symbols 2–11 across 40 PRB"*, which is channel
identification.

```
carrier offset +1200.0 Hz  (+0.000 ppm at 3750 MHz)   CP match 1.00
```

A low CP match means the slot is empty, or the numerology or the sample
alignment is wrong — it will say so rather than draw a confident grid of noise.

### Timing — arrival time against the time `seq_id` implies

`VALIDATION.md` names this as the tool's blind spot: it measured *position*,
never *time*. libpcap stamps every packet and the tool used to discard it.

```
expected = cell × 15.625 µs      what seq_id says the packet is for
actual   = h->ts − frame start   when it really turned up
```

Per lane: the jitter range, plus a count of out-of-order and duplicate cells.
A sender that is correctly addressed but late now shows up as jitter rather
than being invisible.

---

## Geometry is derived, not assumed

Four inputs — sample rate, numerology, samples per packet, sample format —
and the OFDM geometry falls out with them:

```
scs   = 15 kHz × 2^mu
nfft  = sample_rate / scs
cp1   = round(nfft × 0.0703125)
cp0   = samples_per_slot − 14×nfft − 13×cp1
```

For this testbed that gives exactly the published numbers, and the tool
checks that it closes before enabling the Analyse tab:

```
122.88 Msps, mu=1   ->  nfft 4096, cp 352/288, 14 symbols
                        352 + 13×288 + 14×4096 = 61,440 = one slot, to the sample
                        bin spacing = 30 kHz = one subcarrier, exactly
```

If it does not close, Analyse is disabled and says why, rather than producing
a plausible wrong answer.

```bash
--prb <n>      occupied resource blocks   (default: from the FFT size; use 273 here)
--fc <MHz>     carrier, only to express offsets in ppm   (default 3750)
```

---

## Controls

```
RUN / STOP     red while running, green while stopped, top right on its own
Single         resume, then stop on the next frame

View           Afterglow (Off / Fade / Hold) · Clear trace · Auto scale
               Zoom (slot range) · Hide silent after
Measure        Cursors · DC offset · Lock to signal · Re-lock
Compare        Save reference · Overlay / Difference
Analyse        lane · slot · Analyse · dB range
Timing         per-lane jitter, out-of-order, duplicates
Stop when      cells below N · energy in slot · a sender goes silent ·
               capture loses packets
```

Stopping discards packets at the top of `on_packet` while `pcap_loop` keeps
draining the socket, so the kernel ring never overflows and RUN resumes on
live data rather than a backlog. Staleness and blanking are suppressed while
stopped — a frozen screen stays on screen.

---

## What it was tested against

A synthetic OFDM slot with a tone in a known resource block and a deliberate
carrier offset, pushed through the real capture path:

```
geometry          nfft=4096 cp0=352 cp1=288 nsym=14 nprb=273   ofdm_ok=1
tone in PRB 100   grid peak at PRB 100  (−23.0 dB)
offset 1200 Hz    measured +1200.0 Hz,  CP match 1.000
```

Plus the earlier behaviour, re-run against this source: three interleaved
senders stay in separate lanes with no amplitude bleed in any phase
relationship; STOP freezes every number and RUN resumes; and each **Stop when**
condition fires only when it should.

---

## Still true, and still a limitation

The trace is min/max of **I only**. Q is read for the DC mean and for the
analysis, but is not plotted. The true envelope is `√(I² + Q²)`; I alone
swings through zero on every carrier cycle even when the envelope is flat, so
some of the fine texture is phase rotation rather than amplitude.

A lane is a **transmitter**, not a direction. With two gNBs on the link
"downlink" is no longer one thing, and this does not pretend otherwise.

No constellation or EVM yet. A scatter plot without equalising against DMRS
first would look like a smear regardless of how good the signal is, so it is
worth doing properly or not at all.
