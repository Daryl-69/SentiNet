# SentiNet: 1:20 demo video script

One continuous screen recording: terminal → dashboard → terminal. The timings are real. At speed 1, one simulated
minute passes every second, so once you press **Start** at 0:15, **video second ≈ network-clock minute + 15**
(08:10 → 0:25, 08:37 → 0:52, 08:48 → 1:03).

## Before you record (5 minutes)

1. Run the app once beforehand (`run_windows.bat` / `bash run.sh`) so the first-time install is already done. Close it
   again with Ctrl+C.
2. Close heavy apps. In a dry run, the dashboard's **"model step"** readout should stay under ~900 ms. If it is
   higher, the clock runs slower than one minute per second and the timings below stretch; the story is the same.
3. Terminal: font size ~18, window maximised, in the SentiNet folder. Browser: full screen (F11), zoom 90 % so the
   KPIs, the timeline and the 64-futures chart are all visible without scrolling.
4. Leave the sidebar defaults: **Simulated network**, speed **1.0**, **Auto demo script** ticked, seed 7.
   The run is deterministic, so the same attack happens at the same minute every time.
5. Do one full dry run with the script below, then record.

## The script

| Time | On screen (what you do) | Voice-over (≈ 190 words) |
|---|---|---|
| **0:00–0:12** | **Terminal.** Type `python -m sentinet app` (or double-click `run_windows.bat`) and press Enter. The SentiNet banner and the `[ok]` checks appear: world model 169,736 parameters, 64 futures × 10 min, Shapley + ATT&CK, signed receipts, traffic sources, 100 % offline. The last line is `Dashboard http://localhost:8501`. | "This is SentiNet, our world model for forecasting network attacks. Everything runs offline on this laptop: the model loads in seconds, with explanations, MITRE ATT&CK mapping and signed receipts." |
| **0:12–0:15** | The browser opens on the **Live monitor**. Press **Start**. | "We're watching a live company network: twenty workstations, one second per minute." |
| **0:15–0:25** | Clock 08:00–08:10. Move the mouse over the **64 imagined futures** chart, then the host graph. | "Every minute, traffic becomes a network state: 47 features plus a host graph. The model imagines 64 futures, ten minutes ahead." |
| **0:25–0:50** | **08:10:** the red **✕ attack** marker appears; the stage strips turn orange (Reconnaissance). Around 08:30 (0:45) the risk curve starts to bend upward. Point at it. | "At 8:10 an attacker starts probing our web server. A normal IDS would label each request separately and see little. SentiNet sees the pattern building: watch the risk curve rise." |
| **0:52** | **08:37: ALARM.** The red banner appears. The KPIs read 100 %, Initial Access, TA0001, target 10.10.2.20. The alert card shows `T1595.003` wordlist scanning and the next technique with its mitigation. | "8:37: alarm. 100 % chance of infiltration within ten minutes, predicted stage Initial Access, target: the web server. And it says why: wordlist scanning from the attacker's IP, plus the mitigation to apply." |
| **0:52–1:03** | Point at the **truth** strip: still orange, so nothing has broken in yet. Around **08:48–08:50 (1:03–1:05)** a red block appears on the truth strip. | "Notice the ground truth: no break-in yet. At 8:48 the real exploit lands. We warned eleven minutes earlier." |
| **1:04** | Click the orange **Isolate 10.10.2.20** button. | "One click isolates the target." |
| **1:05–1:12** | The blue **🛡 action** marker appears, the risk drops to **0 %**, the KPIs turn Benign, and the truth strip goes grey. | "The attack chain is broken, and the forecast drops to zero. Every forecast is sealed in an Ed25519-signed Merkle receipt." |
| **1:12–1:20** | **Alt-Tab to the terminal.** It has logged the story by itself: `ATTACK` 08:10 → `ALERT` 08:37 → `ACTION` host isolated → `attack chain broken`. | "Forecast it, explain it, stop it, before the attacker gets in. SentiNet: Team Resurrección, SIH 26153." |

## If something goes off-script

- **The alarm is late or early by a minute or two:** keep talking. Say the times you actually see; the gap to the
  break-in is what matters.
- **You missed the Isolate moment:** isolating at any point before about 09:30 still breaks the chain and drops the
  risk.
- **You want a second take:** press **Reset**, then **Start** again. It is the same deterministic run.
- **Showing a real network instead:** choose **Live capture** (as Administrator with Npcap on Windows, `sudo` on
  Linux/macOS). Real traffic will not contain an attack on cue, so keep the simulated run for the video.

## What the terminal shows (for reference)

```
  [ok] World model      169,736 parameters · graph network + temporal Transformer + latent dynamics (3.2s)
  [ok] Forecast         64 imagined futures x 10 min ahead, every 60 s · alarm at 86%
  [ok] Explainability   exact Shapley values · attention · MITRE ATT&CK / CAPEC knowledge base
  [ok] Integrity        every forecast in an Ed25519-signed Merkle receipt
  [ok] Traffic sources  simulated network · replay PCAP/CSV · live capture (4 interfaces found)
  [ok] Privacy          100% offline: no cloud, no external API calls
  [ok] Dashboard        http://localhost:8501 (0.9s)

  Live events appear below. Ctrl+C to stop.

  08:00  INFO    live monitor started on the simulated network (auto demo script)
  08:10  ATTACK  attack started: web_exploit from 193.200.105.11
  08:37  ALERT   100% infiltration within 10 min · forecast Initial Access · target 10.10.2.20 · T1595.003 Active Scanning: Wordlist Scanning (web content enumeration)
  08:50  ACTION  host isolated: 10.10.2.20
  08:50  ACTION  attack chain broken: web_exploit can no longer continue
```

Streamlit's own start-up messages are kept out of the terminal. They go to a log file (`sentinet_app.log` in the
system temp folder), which is only printed if the dashboard fails to start.
