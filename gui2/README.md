# gui2 — scope view, with the uplink named explicitly

Same display as `gui`: two stacked plots, downlink above uplink, a fixed
slot axis 0–19, and a min/max envelope so a slot with power shows as a
spike and a silent slot as a flat line.

One difference, and it is the reason this directory exists.

## What changed, and why

`gui` decides direction like this:

```c
int is_dl = (memcmp(bytes + 6, g_dl_mac, 6) == 0);
dir_t *d  = is_dl ? &g_dl : &g_ul;
```

Downlink is "from the gNB". Uplink is **everything else** — which is only
the UE while exactly two devices sit on the mirror.

Put a third sender of `0xAEFE` frames on the same mirror and it breaks in a
specific, recognisable way. Each device writes its own `seq_id` counting
1…640, and the two sequences interleave:

```
device A:  300, 301, 302 …
device B:    1,   2,   3 …
as seen:   300,   1, 301,   2, 302,   3 …
```

Every other packet steps backwards, so the frame is cut almost immediately
and `cells UL` collapses to 2 or 3. The downlink is unaffected — one
device, one sequence — so you see a badly asymmetric picture:

```
543/640 cells DL     2/640 cells UL     drop=0
```

`drop=0` is the tell. Nothing was lost; the uplink was never assembled.

`gui2` takes an optional third argument naming the UE. Anything from a
third address is then counted and discarded rather than mixed in:

```c
if (!is_dl && g_have_ue && memcmp(bytes + 6, g_ue_mac, 6) != 0) {
    g_other++;
    return;
}
```

## Run

```bash
bash build.sh
sudo setcap "cap_net_raw,cap_net_admin=eip" ./build/src/split_scope
./run.sh sfp1 <gnb-mac> <ue-mac>
```

Note there is **no space after the comma** in `setcap`, and the capability
is lost on every rebuild. Do not start it with `sudo`: sudo discards the X
authority cookie and the window will not open.

The third argument is optional. Without it the behaviour is identical to
`gui`, and the status bar says so in amber rather than pretending
otherwise.

## Reading the status bar

| | |
|---|---|
| `other=0 (ignored)` | only the gNB and the named UE are on the mirror |
| `other` climbing | a third device is sending; those frames are being discarded |
| `UL = every non-gNB sender` | no UE given — uplink is a guess |
| `clean drop=0 ifdrop=0` | nothing lost; the trace is complete |

If `other` climbs **and** `cells UL` goes to 640, the third-device theory
was right and naming the UE fixed it.

## Finding the MACs

```bash
sudo timeout 5 tcpdump -i sfp1 -nn -e 'ether proto 0xaefe' 2>/dev/null \
  | awk '{print $2}' | sort | uniq -c | sort -rn
```

Three or more source addresses means this directory is the version you
want. Two means `gui` would have worked and something else is wrong.

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

- Capture runs on its own thread; the render thread only reads the shared
  envelope arrays. At 128,000 packets/second the capture path must never
  wait on the renderer.
- `ImGuiConfigFlags_ViewportsEnable` is deliberately **off** — undocked
  windows become separate X windows, which is unreliable over `ssh -X`.
- The CMake skeleton (`CMakeLists.txt`, `cmake/`, `build.sh`) is from a
  colleague's ImGui/ImPlot starter project.
