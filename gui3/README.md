# gui3 — one lane per source MAC

Same scope display as `gui` and `gui2` — min/max envelope, fixed slot axis
0–19, persistence band — but the capture is split by **source address**
rather than by a guess about direction.

```bash
./run.sh sfp1
```

No arguments beyond the interface. Senders are discovered as they appear.

---

## Why this exists

`gui` and `gui2` decide direction with one question:

```c
int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
dir_t *d  = is_dl ? &g_dl : &g_ul;
```

Downlink is "from the gNB". Uplink is **everything else**. That holds only
while exactly two devices sit on the mirror.

The setup it breaks on: wnbox-4 (gNB) and an FPGA (also a gNB) transmitting
**simultaneously** to wnbox-7 (UE). Three senders. The FPGA's *downlink*
gets classified as uplink, and two `seq_id` sequences land in one
accumulator.

### It fails two different ways, and one of them is silent

Both were reproduced against the real `gui2` source with synthetic traffic
(`seq_id` 1…640 per sender, fully interleaved):

| the FPGA relative to the UE | `cells DL` | `cells UL` | uplink trace shows |
|---|---|---|---|
| in phase | 640 | **640** | the **FPGA's** amplitude, not the UE's |
| 300 cells out of phase | 640 | **2** | nothing |

The second is the one that was observed on wn-box 7, and it is the *lucky*
case — it announces itself. The first reports a perfect `640/640` while
drawing the wrong device's signal, because two senders writing the same
cell index never step backwards and so never trip the frame-wrap test.
One device simply overwrites the other and nothing anywhere says so.

A tool that reports `640/640` while showing you the wrong transmitter is
worse than one that reports `2/640`.

### What this version does instead

```c
lane_t *L = lane_for(bytes + 6);
if (!L) return;
```

The source address alone picks the lane. No inference about which end of
the link a sender is on, so a second transmitter cannot land in someone
else's sequence. Each lane keeps its own `seq_id` state, its own envelope
and its own cell count.

On the same synthetic input, in both phase conditions:

```
lanes discovered: 3
  lane 0  src bc:24:11:ec:73:d3   cells=640
  lane 1  src bc:24:11:aa:bb:cc   cells=640
  lane 2  src 00:0a:35:11:22:33   cells=640
  peak hi: A=0.3052  B=0.0092  C=0.1526     <- no bleed between lanes
```

---

## Build and run

```bash
bash build.sh
sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/split_scope3
./run.sh sfp1
```

**No space after the comma** in `setcap`, and the capability is lost on
every rebuild. Do **not** start it with `sudo`: sudo discards the X
authority cookie and the window will not open.

Naming senders is optional and changes nothing about the measurement — it
fixes lane order, colour and label so runs are comparable:

```bash
./run.sh sfp1 \
    bc:24:11:ec:73:d3=gNB-wnbox4 \
    bc:24:11:aa:bb:cc=UE-wnbox7  \
    00:0a:35:11:22:33=FPGA-gNB
```

Up to 6 lanes. Beyond that, packets are counted and discarded, and the
header says so rather than folding them into an existing lane.

---

## Reading the header

```
sfp1   3 senders
clean  drop=0 ifdrop=0
187341 pkt/s   11.54 Gbit/s on the mirror   bad=0 trunc=0
  gNB-wnbox4   src bc:24:11:ec:73:d3   640/640 cells   64001 pkt/s
  UE-wnbox7    src bc:24:11:aa:bb:cc   640/640 cells   64002 pkt/s
  FPGA-gNB     src 00:0a:35:11:22:33   640/640 cells   59338 pkt/s
```

| | |
|---|---|
| `drop > 0` | **you** were too slow; the traces have holes |
| `ifdrop > 0` | the card lost it, before your process |
| `n/640 cells` | how much of the last frame that sender's lane assembled |
| `(silent)` | the sender is known but sent nothing this frame |

### The Gbit/s figure is the point of this header

`drop` and `ifdrop` **cannot see loss inside the switch**. If the mirror
port's line rate is below the sum of the senders' rates, the switch
discards before anything reaches the card, and the capture calls itself
clean while cells sit below 640.

Each eCPRI stream is roughly

```
64,000 pkt/s × 7702 B = 493 MB/s = 3.95 Gbit/s
```

so three simultaneous streams need about **11.8 Gbit/s**. On a 10G mirror
port that is oversubscribed and some fraction is dropped silently. Compare
the displayed figure against:

```bash
ethtool sfp1 | grep -iE "speed|duplex"
```

If the number on screen is close to the link speed, a low cell count is the
switch, not this program and not the sender. That is the one failure mode
the tool is structurally blind to, which is why the rate is shown rather
than left for you to work out.

---

## What it still cannot do

**It measures position, not time.** The slot index comes from `seq_id`,
which the sender writes as an address. A transmission that is correctly
addressed but late still reports its correct slot, so a pure emission
timing fault is invisible here. An oscilloscope on the same link will see
it; this will not.

**It measures energy, not bits.** Nothing is demodulated or decoded.

**It does not label direction.** A lane is a transmitter, not a direction.
With two gNBs on the link, "downlink" is no longer one thing, and the tool
no longer pretends otherwise — which is the whole point.

---

## Dependencies

```bash
sudo apt install -y cmake pkg-config libglfw3-dev libglew-dev \
                    libgl1-mesa-dev libpcap-dev
```

ImGui and ImPlot are fetched at configure time by CPM, so the build machine
needs outbound access to `github.com`. If it has none:

```bash
cmake -S . -B build \
  -DCPM_imgui_SOURCE=/path/to/imgui-src \
  -DCPM_implot_SOURCE=/path/to/implot-src
```

## Notes

- Capture runs on its own thread; the render thread reads `g_nlanes` and
  then only lanes below that index. Lanes are append-only and the count is
  published last, so a lane is never read before its address is written.
- Lane lookup is a linear scan of at most 6 six-byte compares. At 190,000
  packets/second that is nothing next to the 1920-sample min/max loop.
- `ImGuiConfigFlags_ViewportsEnable` is deliberately **off** — undocked
  windows become separate X windows, unreliable over `ssh -X`.
- The CMake skeleton (`CMakeLists.txt`, `cmake/`, `build.sh`) is from a
  colleague's ImGui/ImPlot starter project.
