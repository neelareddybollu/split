# Split 8 fronthaul scope

A digital-oscilloscope view of a Split 8 fronthaul link. It captures raw eCPRI
frames off a mirror port, sorts them into one lane per transmitter, and draws
the waveform the way a scope would: a min/max envelope in linear amplitude
about a true zero baseline. On top of that it can analyse a single slot —
cyclic-prefix correlation and a resource grid — and audit the packet sequence
and arrival timing.

It is a measurement instrument, not a monitor. Where it cannot measure
something honestly it refuses and says why, rather than drawing a plausible
wrong answer.

---

## Build and run

From the top of the checkout:

```bash
bash build.sh
sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/split8_analyser
./build/src/split8_analyser <iface> --prb 273
```

`<iface>` is the port the fronthaul is mirrored to. It needs an MTU of at least
9000 — the frames are 7702 bytes.

Three things that bite every time:

- **No space after the comma** in `setcap`. `cap_net_raw, cap_net_admin` fails.
- **The capability is wiped by every rebuild.** Re-run `setcap` after
  `build.sh`, always.
- **Do not launch it with `sudo`.** sudo discards the X authority cookie and the
  window never opens. `setcap` is what grants raw-socket access; the program
  itself runs as you.

At startup it prints the geometry it derived:

```
link: 122.88 Msps, mu=1, 1920 samples/packet
  -> 61440 samples/slot, 32 packets/slot, 20 slots/frame, 640 packets/frame
  -> cell 15.625 us, slot 500 us, 64000 packets/s per sender
lanes: 0 named, up to 6 discovered
ofdm: 4096-point FFT, cp 352/288, 14 symbols, 273 PRB, bin = subcarrier = 30 kHz
```

Check those numbers match the link before reading anything else off the screen.

### Naming senders

Optional, and it changes **no measurement** — it only fixes a sender's lane
position, colour and label so runs are comparable:

```bash
./build/src/split8_analyser <iface> --prb 273 \
    aa:bb:cc:dd:ee:01=gNB \
    aa:bb:cc:dd:ee:02=UE
```

Unnamed senders are discovered as they appear, up to 6 lanes. There is no
concept of uplink or downlink: **a lane is a transmitter, not a direction.**
With two gNBs on a link "downlink" is not one thing, and the tool does not
pretend otherwise.

### Options

```
--rate <Msps>     sample rate                     (default 122.88)
--mu <n>          numerology 0..4                 (default 1)
--spp <n>         samples per packet              (default 1920)
--bits <n>        sample width, 16 only           (default 16)
--ethertype <hex>                                 (default 0xaefe)
--seq-base <0|1>  seq_id of the first cell        (default 1)
--hdr-off <n>     frame start to eCPRI header     (default 14)
--iq-off <n>      eCPRI header to IQ              (default 8)
--version <n>     expected eCPRI version, -1 skip (default 1)
--msgtype <n>     expected message type,  -1 skip (default 0)
--prb <n>         occupied resource blocks        (default: from the FFT size)
--fc <MHz>        carrier, only to express offsets in ppm   (default 3750)
-c <file>         the same keys from a file, "key = value" per line
```

#### `--prb` is not optional in practice

Without it the tool guesses `(nfft * 9) / 10 / 12` — a placeholder meaning
"assume about 90% of the FFT is occupied", which at a 4096-point FFT gives 307.
A 100 MHz carrier at 30 kHz subcarrier spacing is **273 PRB** = 3,276
subcarriers = 98.28 MHz.

It matters because the resource grid maps blocks to subcarriers as
`sc = -(nprb*12)/2 + prb*12 + t`. At 273 that spans −1638…+1637; at 307 it spans
−1842…+1841. Same signal, grid started 204 subcarriers low, so **every PRB index
shifts by 17** and the plot is 34 blocks wider than the signal. Energy really in
PRB 100 is drawn at PRB 117, with nothing on screen saying anything is wrong.

The number comes from the carrier's configuration, not from anything the tool
can measure.

---

## What the display shows

One stacked plot per transmitter, sharing an x axis of **slot number** across
one radio frame.

For every packet the tool keeps the smallest and largest I sample and fills the
band between them — the same per-pixel-column decimation a scope does. The
bright band is the live frame; the dim band behind it is afterglow.

Packets are placed by **cell index**, derived from `seq_id`, not by arrival
order. A missing packet leaves a zero-filled hole at the right offset instead of
pulling the rest of the waveform forward. A tool that appended in arrival order
would shear its own trace on any loss.

The header line carries the link's health:

```
clean  drop=0 ifdrop=0   128010 pkt/s   7.89 Gbit/s
  src 50:7c:6f:66:e4:aa  (lane 1)  640/640 cells  64005 pkt/s  peak 0.1939
```

`drop` and `ifdrop` are libpcap's own counters and they are **blind to loss
inside the switch**. If the senders' combined rate approaches the mirror port's
line rate, cells sit below 640 on a capture that calls itself clean. That is
what the Gbit/s figure is for: three senders at 3.96 Gbit/s each need 11.87, and
a 10G mirror will quietly deliver about 84% of it. **Treat anything below
640/640 as a measurement you cannot trust.**

A lane that stops transmitting dims, then blanks, so a dead sender is visibly
dead rather than frozen.

---

## Geometry is derived, not assumed

Four inputs — sample rate, numerology, samples per packet, sample width — and
the rest falls out:

```
samples/slot = rate / 1000 / 2^mu          packets/slot = sps / spp
slots/frame  = 10 * 2^mu                   cells/frame  = pps * slots
cell_us      = spp / rate                  slot_us      = 1000 / 2^mu

scs   = 15 kHz * 2^mu
nfft  = rate / scs
cp1   = round(nfft * 144/2048)
cp0   = samples_per_slot - 14*nfft - 13*cp1
```

The tool checks the slot closes to the sample before enabling any OFDM work:

```
122.88 Msps, mu=1  ->  nfft 4096, cp 352/288, 14 symbols
                       352 + 13*288 + 14*4096 = 61,440 = one slot, exactly
                       bin spacing = 30 kHz = one subcarrier, exactly
```

Configurations it rejects outright rather than fudging: a sample width other
than 16 bits, a rate giving a fractional samples-per-slot, a slot not divisible
by the packet size, and a frame too large for a 16-bit `seq_id`.

**OFDM analysis is restricted to mu = 1.** The long cyclic prefix exists to
align symbols with the 0.5 ms half-subframe boundary, so where it sits depends
on the slot length: at mu=1 a slot *is* 0.5 ms and there is one long prefix at
symbol 0; at mu=0 there are two per slot; at mu=2 one per *pair* of slots. This
code places one at symbol 0 of every slot, which is correct only at mu=1, so
Analyse refuses elsewhere. Everything else stays numerology-agnostic.

---

## Controls

```
RUN / STOP     red while running, green while stopped, top right on its own
Single         resume, then stop on the next frame

View           Afterglow (Off / Fade / Hold) - Clear trace - Auto scale
               Zoom (slot range) - Hide silent after
Measure        Cursors - DC offset - Lock to signal - Re-lock
Compare        Save reference - Overlay / Difference
Analyse        lane - Follow the signal - slot - Analyse - dB range
               + resource-grid heatmap
Timing         per-lane jitter, out-of-order, duplicates
Stop when      cells below N - energy in slot (+ level %) -
               a sender goes silent - capture loses packets
```

**RUN/STOP** discards packets at the top of the capture callback while
`pcap_loop` keeps draining the socket, so the kernel ring never overflows and
RUN resumes on live data rather than a backlog. Staleness and blanking are
suppressed while stopped — a frozen screen stays on screen.

**Afterglow** is a phosphor model, not a high-water mark. *Fade* decays towards
the live trace with a settable time constant; *Hold* never decays; *Off* shows
only the live frame. Worth remembering when reading the screen: **in Fade or
Hold, a burst you can see may belong to a frame that has already gone.**

**Lock to signal** aligns the trace by normalised cross-correlation against a
slowly adapted reference, not by peak-finding, so it works with one burst,
several, or a broad waveform, and reports NO LOCK rather than locking onto
noise. Re-lock also clears persistence, because a band accumulated at the old
alignment describes a position the trace no longer occupies.

**Stop when** arms a condition and freezes the screen at the moment it fires,
showing why. With nothing ticked it stops on the next frame — a scope's SINGLE.

Two things about it that are easy to get wrong. **Armed is a separate switch**:
ticking a condition says *what* to stop on, `Armed` is what makes any of them
evaluate — look for the yellow `ARMED` on the right. And **pressing RUN clears
Armed**, so the order is RUN first, tick Armed last.

**energy in slot** judges the slot against the frame's own peak burst, at a
settable percentage, never below 1% of full scale. An absolute threshold is
useless here: no slot on a live link is ever truly empty — thermal noise,
quantisation and DC leakage all sit well above the least significant bits — so
a low fixed floor fires on the first frame every time regardless of content.
The tab shows the measured span and the threshold side by side, so you can see
what it is comparing before you arm it.

---

## Analyse — cyclic-prefix correlation and the resource grid

Pick a lane, press **Analyse**. The capture path copies one slot's raw IQ aside
as it goes past and the analysis runs **once**, off the hot path, so a
4096-point FFT never touches the capture rate.

### Arming

**The buffer fills strictly in order**, `k = 0 … 31`, and any packet that isn't
the one expected restarts it. That single rule makes a lost packet, a
reordering and the frame wrap all self-correcting without detecting any of them,
and it guarantees the slot handed to the FFT came from **one** radio frame.

**Only a frame with signal in that slot is accepted.** SSB repeats every 20 ms
while a radio frame is 10 ms, so roughly half of all frames are empty in any
given slot. The threshold is a quarter of the lane's own recent peak, never
below four times the burst floor — high enough that DC leakage, which sits far
above the floor, does not pass as signal. Rejected frames are counted and shown.

**Follow the signal** (default on) aims at the strongest slot in the lane and
re-reads it every frame, so a drifting burst does not have to be chased by hand.
Untick it to pin a slot.

**It works while STOPPED.** Freeze the screen, then measure. Nothing else runs
while stopped — no lane discovery, no counters, no trace — only the armed grab.

### Cyclic-prefix correlation

Every OFDM symbol begins with a copy of its own tail. Correlating the prefix
against the body one symbol period later gives two things at once:

```
r = sum over the prefix of  x[n] * conj(x[n + nfft])

|r| / sqrt(Pa*Pb)     how well they match -> confirms sample alignment,
                      FFT size and numerology, all three at once
-arg(r) / (2*pi*Tu)   carrier frequency offset, because a frequency error
                      rotates the signal by 2*pi*df*Tu across that interval

                      Tu = nfft / sample_rate = 33.33 us here
```

A full 2π of phase is therefore 30 kHz, so the frequency measurement is
**unambiguous only to ±15 kHz** — half the subcarrier spacing. A true +20 kHz
offset reads as −10 kHz. Keep that in mind before believing a small number.

This measures the waveform itself. It needs no pattern to lock onto, works on a
stream that never assembles a frame, and makes no assumption about what `seq_id`
means — which makes it the right instrument whenever `seq_id` itself is in
question.

```
carrier offset +1200.0 Hz  (+0.000 ppm at 3750 MHz)   CP match 1.00
```

A high CP match is also independent evidence that the configured sample rate and
numerology are right: a wrong `nfft` correlates the prefix against the wrong
part of the symbol and the match collapses.

### The resource grid

A 14 × nPRB heat map of power in dB, symbol against resource block:

```
bin   = (sc + nfft) mod nfft
dBFS  = 10*log10( P / (12 * nfft^2 * FS^2) )
```

This is what turns *"slot 10 is busy"* into *"4 symbols across 20 PRB"*, which
is channel identification — an SSB is exactly 20 PRB by specification, a CORESET
is whatever it was configured as.

A useful sanity check lives in the picture itself: **DC leakage appears at the
centre PRB.** At 273 PRB that is block 136. If the stripe is there, the FFT, the
bin folding and the PRB indexing are all working.

---

## Timing — the sequence, and arrival against the time `seq_id` implies

libpcap stamps every packet. The scope would otherwise measure *position* and
never *time*.

```
expected = cell * 15.625 us      what seq_id says the packet is for
actual   = h->ts - frame start   when it really turned up
```

### What the counters mean

**Out-of-order** counts *packets* whose `seq_id` is below the previous packet's
by at most half a frame. One packet carries one cell, so packets and cells are
the same count here. A larger backward step is read as the frame wrap:

```
cell < last_cell && last_cell - cell <= cells/2   ->  out-of-order
cell < last_cell && last_cell - cell >  cells/2   ->  frame wrap
```

**Duplicate** counts packets landing on a cell this frame has already written.
The later packet overwrites the earlier one.

**Both are cumulative totals since the program started**, per lane, never reset
by RUN/STOP, Clear trace or Re-lock. A single reading says little — a count with
no time base cannot tell you whether anything is happening *now*. Sample twice
and subtract:

```
3156 - 3068 = 88 over 20 s  ->  4.4 per second
```

A cumulative counter that is **flat** is the strong reading. A lane sitting at 7
through 1.28 million packets is proof the stream is clean in a way a small
number never is.

**They measure different things, and the ratio is informative.** One late packet
counts 1, but it drags the write position backwards and everything after it
re-writes cells the frame already had. 88 out-of-order producing 2,879
duplicates means each backward step went back about 33 cells.

### Blind spots

A packet arriving early, still ahead of `last_cell`, is invisible — only
backward steps are seen. A genuine reordering of more than half a frame is
misread as a wrap. And the tool cannot distinguish network reordering from a
transmitter repeating its own numbering; both look identical on the wire.

Jitter is re-zeroed at every `cell == 0`, so the window shown is per frame, not
cumulative. At 64,000 pkt/s through libpcap, a ±100 µs window is more likely
capture-side scheduling than a fronthaul fault — compare against a
hardware-timestamped capture before calling it a timing problem.

---

## Cursors

```
dx 0.911 = 455.7 us = 55991 samples = 29.2 packets   1/dt = 2.195 kHz
dy 0.20000 = 6554 counts
```

`dx` is reported in slots, microseconds, samples and packets at once, plus
`1/dt` so a repetition interval reads off directly as a frequency.

`dy` is the gap between the two horizontal cursors in normalised amplitude —
each 16-bit sample divided by 2¹⁵ = 32768, so the axis runs −1.0 to +1.0.
`counts` is `dy × 32768`, the raw integer the device put in the packet. Full
scale is 32767, so `counts` is the number that shows headroom to clipping: a
peak of 0.8678 is 28,436 counts, 87% of full scale.

---

## Limitations

**The trace is min/max of I only.** Q is read for the DC mean and for the
analysis, but is not plotted. The true envelope is `sqrt(I² + Q²)`; I alone
swings through zero on every carrier cycle even when the envelope is flat, so
some of the fine texture is phase rotation rather than amplitude. The alignment
correlation keys on the per-packet span `(hi − lo)`, which brackets the whole
swing and is far less phase-sensitive than I itself.

**`seq_id` is assumed to be a 16-bit frame address, 1..640.** Frame assembly,
cell placement, the completeness count and both sequence counters all rest on
that. A sender that formats the eCPRI sequence field differently — for example
as an 8-bit `ecpriSeqid` plus an E bit and a 7-bit subsequence, which is what
the eCPRI specification defines for an IQ-data message — is parsed wrongly, and
nothing on screen says so. If one lane's counters behave very differently from
another's on the same wire, check the raw header bytes before trusting either:

```bash
sudo tcpdump -i <iface> -nn -c 4 -s 32 -xx 'ether proto 0xaefe and ether src <mac>'
```

`-xx`, not `-x`: `-x` omits the Ethernet header and every offset shifts by 14.
Bytes 14–21 are version, message type, payload size, `pc_id`, sequence field.

**Mirror loss is invisible to `drop`/`ifdrop`.** See the Gbit/s note above.

**No constellation or EVM.** A scatter plot without equalising against DMRS
first would be a smear regardless of how good the signal is — worth doing
properly or not at all.
