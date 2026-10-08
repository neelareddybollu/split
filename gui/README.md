# gui — graphical front end

Live capture from a mirror port, with a scrolling power waterfall per
direction instead of a text table.

Same capture and accumulation code as `live2.c` in the repository root. The
only difference is the output stage: `live2.c` prints, this draws. It also
still prints the text block to stdout, so one process gives both views.

## Dependencies

```bash
sudo apt install -y cmake pkg-config libglfw3-dev libglew-dev \
                    libgl1-mesa-dev libpcap-dev
```

ImGui and ImPlot are fetched at configure time by CPM — nothing to vendor,
but the build machine needs outbound access to github.com.

If it does not, point CPM at sources that already exist:

```bash
cmake -S . -B build \
  -DCPM_imgui_SOURCE=/path/to/imgui-src \
  -DCPM_implot_SOURCE=/path/to/implot-src
```

## Build

```bash
bash build.sh
ls build/src/imgui_app
```

## Run

```bash
sudo ./run.sh <iface> <dl-src-mac>
sudo ./run.sh sfp1 bc:24:11:ec:73:d3
```

The MAC is the source address of the downlink direction. Packets from that
address go in the DL waterfall, everything else in the UL waterfall.

`no window - is DISPLAY set?` means the build is fine and there is no
display. Set `$DISPLAY`, or use X11 forwarding, or a console.

## What it shows

- **Header** — packets, frames and cells per direction, plus `drop` /
  `ifdrop` from `pcap_stats`. Green when clean, red when lossy. Watch this
  first: a plot drawn from a lossy capture is worse than no plot.
- **Table** — per-slot mean power in dBFS for the most recent frame, both
  directions. Silent slots are hidden.
- **Two waterfalls** — 20 slots across, 400 frames down, so 4 seconds of
  history at 100 frames/second. Each row is one 10 ms frame.

Per-slot value is the **mean** of I² + Q² over the slot's 61,440 samples,
converted to dBFS against full scale 32767. Not a peak sample.

The waterfall keeps every frame, so a signal that appears only in some
frames shows as stripes, and the vertical spacing between stripes is its
period. The one-line-per-second text output cannot show that.

## Notes

- Capture runs on its own thread. The render thread only reads the shared
  waterfall arrays. At 128,000 packets/second the capture path must never
  wait on the renderer, or the kernel buffer overflows.
- `ImGuiConfigFlags_ViewportsEnable` is deliberately **off**. Undocked
  windows become separate X windows, which is unreliable over `ssh -X`.
  Docking is on, so panels can still be rearranged inside the one window.
- Do not run this and `live2` at the same time. Each pcap handle gets its
  own copy of every packet, so two processes double both the kernel copy
  and the squaring loop.

## Credit

The CMake skeleton (`CMakeLists.txt`, `cmake/`, `build.sh`) is from a
colleague's ImGui/ImPlot starter project. `src/main.cpp` and
`src/CMakeLists.txt` are this project's.
