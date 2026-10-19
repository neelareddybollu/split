# split — a live Split 8 fronthaul analyser

Captures eCPRI frames off a switch mirror port and shows what each slot of
the 10 ms radio frame is carrying, in both directions, in real time.

```
7702 bytes x 128,000 packets/s  =  986 MB/s  =  7.9 Gbit/s, zero loss
```

The sequence field in the eCPRI header is an **address**, not a counter
(`cell = seq_id - 1`, `slot = cell / 32`), so a lost packet leaves a hole
rather than shifting everything after it. Every tool here reports its own
kernel and interface drop counts once a second; a lossy capture says so on
screen rather than drawing a clean but false picture.

---

## The tools

Each `live*.c` is one standalone program. They are a progression, not
alternatives — later ones keep what earlier ones did.

| file | what it adds |
|---|---|
| `live3.c` | per-slot peak dBFS, bar display or `-g` oscilloscope trace, TDD-violation alert |
| `live4.c` | per-frame log to stderr: one line per frame, all 20 slot values |
| `live5.c` | `-d` sample decimation, `-t` timing mode (64-byte snaplen, no energy) |
| `gui/` | ImGui/ImPlot scope — DL and UL on linked axes, fixed slot axis 0–19 |

Start with `live3` to see whether the capture is clean and which slots carry
energy, then `live4` or `live5` when you need the per-frame numbers written
out for later analysis.

---

## Build and run

```bash
sudo apt install libpcap-dev
gcc -O3 -march=native -o live5 live5.c -lpcap -lm
```

The interface must be promiscuous and take jumbo frames. Both reset on reboot:

```bash
sudo ip link set sfp1 mtu 9000
sudo ip link set sfp1 up
sudo ip link set sfp1 promisc on
sudo tcpdump -i sfp1 -nn -e -c 5 'ether proto 0xaefe'   # expect length 7702
```

Grant the capability once instead of using `sudo` — note there is **no space
after the comma**, and it is lost on every rebuild:

```bash
sudo setcap "cap_net_raw,cap_net_admin=eip" ./live5
./live5 sfp1 bc:24:11:ec:73:d3
```

The second argument is the **gNB's MAC address**. Frames from it are
downlink; everything else is treated as uplink.

### The GUI

```bash
cd gui && ./build.sh
sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/imgui_app
./run.sh
```

It needs an X server and `$DISPLAY` set — MobaXterm provides one on Windows.
Do **not** start it with `sudo`: sudo discards the X authority cookie and the
window will not open.

`build.sh` fetches ImGui and ImPlot at configure time, so it needs
`github.com`. Offline, point it at local copies:

```bash
cmake -S . -B build -DCPM_imgui_SOURCE=/path/imgui -DCPM_implot_SOURCE=/path/implot
```

---

## Reading the output

| | |
|---|---|
| `drop=+0 ifdrop=+0` | capture is clean — the picture can be trusted |
| `drop > 0` | **you** lost packets; the picture is missing data |
| `ifdrop > 0` | the card or the switch mirror lost them, before you |
| `cells 640/640` | the frame was reconstructed complete |

A dropped packet reads as zero, so loss can create false silence but never
false signal. Anything you can see is real; anything absent is unproven.

---

## What it cannot do

**It measures position, not time.** The slot index comes from `seq_id`, which
the sender writes as an address. A transmission that is correctly addressed
but late still reports its correct slot, so a pure emission-timing fault is
invisible here. An oscilloscope on the same link will see it; this will not.

**It measures energy, not bits.** Channels are identified by their shape in
time and frequency — width in resource blocks, span in symbols, position
relative to the SSB. Nothing is demodulated or decoded.
