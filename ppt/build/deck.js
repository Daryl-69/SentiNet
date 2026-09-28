const pptxgen = require('pptxgenjs');
const path = require('path');
const { icon } = require('./icons');

const IMG = path.join(__dirname, '..', 'img');
const OUT = process.argv[2] || 'SentiNet_SIH26153.pptx';

// palette lifted from the old deck
const NAVY = '1F3B64', NAVY2 = '153E66', BODY = '3A4655', MUTED = '55606B', RED = 'B03A36';
const LBLUE = 'DDE6F3', LBLUE_B = '8EA2C0', PEACH = 'F9E3D8', PEACH_B = 'B28F80', OLIVE = '4F6228';
const DARK = '1B3A5C', YEL = 'FFD966', WHITE = 'FFFFFF', GREYB = 'A6A6A6';
const SERIF = 'Times New Roman', SANS = 'Calibri';

const pres = new pptxgen();
pres.layout = 'LAYOUT_WIDE'; // 13.333 x 7.5, same as the old deck (960 x 540 pt)
pres.title = 'SentiNet — SIH26153';

function T(slide, text, o) {
  slide.addText(text, Object.assign({ isTextBox: true, margin: 0, fontFace: SANS, color: BODY, valign: 'top' }, o));
}
function box(slide, x, y, w, h, fill, line, o = {}) {
  slide.addShape(o.round ? pres.shapes.ROUNDED_RECTANGLE : pres.shapes.RECTANGLE, Object.assign({
    x, y, w, h, fill: { color: fill }, line: { color: line || fill, width: o.lw || 1 },
  }, o.round ? { rectRadius: o.round } : {}, o.shadow ? { shadow: { type: 'outer', color: '000000', opacity: 0.18, blur: 3, offset: 1.5, angle: 90 } } : {}));
}
function heading(slide, text, x, y, w, o = {}) {
  T(slide, text, Object.assign({ x, y, w, h: 0.36, fontFace: SERIF, bold: true, fontSize: 17, color: NAVY, underline: { style: 'sng' }, align: 'center', valign: 'middle' }, o));
}
function header(slide, title, sihSmall = true) {
  slide.background = { color: WHITE };
  slide.addImage({ path: path.join(IMG, 'i29.png'), x: 0.02, y: 0.06, w: 0.95, h: 1.0 });
  slide.addImage({ path: path.join(IMG, 'i81.png'), x: 11.9, y: 0.04, w: 1.33, h: 0.62 });
  if (title) T(slide, title, { x: 1.2, y: 0.1, w: 10.6, h: 0.55, fontFace: SERIF, bold: true, fontSize: 26, color: NAVY, align: 'center', valign: 'middle' });
}
// bold lead + body run pair
const lead = (b, t, br = false, c = RED) => [{ text: b, options: { bold: true, color: c, bullet: { code: '25CF' } } }, { text: t, options: { breakLine: br } }];

(async () => {
  const ic = {};
  const want = { chip: ['FaProjectDiagram', NAVY2], fwd: ['FaForward', NAVY2], map: ['FaRoute', NAVY2], why: ['FaSearchPlus', NAVY2],
    whatif: ['FaChessKnight', NAVY2], base: ['FaLayerGroup', NAVY2],
    w1: ['FaChartLine', WHITE], w2: ['FaBookOpen', WHITE], w3: ['FaSitemap', WHITE], w4: ['FaChessKnight', WHITE], w5: ['FaLink', WHITE], w6: ['FaMicrochip', WHITE],
    lock: ['FaLock', '333333'], coins: ['FaCoins', '333333'], cogs: ['FaCogs', '333333'],
    ind: ['FaIndustry', WHITE], bank: ['FaUniversity', WHITE], gov: ['FaShieldAlt', WHITE], edu: ['FaGraduationCap', WHITE],
    yt: ['FaYoutube', 'E62117'], gh: ['FaGithub', '222222'], wd: ['FaFileWord', '2B579A'], pp: ['FaFilePowerpoint', 'C43E1C'] };
  for (const [k, [n, c]] of Object.entries(want)) ic[k] = await icon(n, c);

  // ───────────────────────── SLIDE 1 — TITLE PAGE ─────────────────────────
  {
    const s = pres.addSlide();
    s.background = { color: WHITE };
    s.addImage({ path: path.join(IMG, 'i29.png'), x: 0.02, y: 0.06, w: 0.95, h: 1.0 });
    s.addImage({ path: path.join(IMG, 'i27.png'), x: 10.7, y: 0.05, w: 2.46, h: 1.16 });
    T(s, 'SMART INDIA HACKATHON 2026', { x: 1.3, y: 0.25, w: 9.3, h: 0.8, fontFace: SERIF, bold: true, fontSize: 38, color: '3E4A61', align: 'center', valign: 'middle' });
    T(s, 'TITLE PAGE', { x: 3.5, y: 1.75, w: 4.5, h: 0.6, fontFace: SERIF, bold: true, fontSize: 28, color: '000000', align: 'center', valign: 'middle' });
    const L = (a, b, bb = false) => ({ text: '', a, b, bb });
    const rows = [
      ['Problem Statement ID – ', 'SIH26153', false],
      ['Problem Statement Title – ', 'AI based Network Attack Forecasting from Network Traffic Data', false],
      ['Theme – Blockchain and Cybersecurity', '', true],
      ['PS Category – Software', '', true],
      ['Team ID – 149775', '', true],
      ['Team Name (Registered on portal) – ', 'Resurrección', true],
    ];
    const ys = [3.05, 3.55, 4.4, 4.9, 5.4, 5.9];
    rows.forEach(([a, b, bb], i) => {
      const r = [{ text: a, options: { bold: true } }];
      if (b) r.push({ text: b, options: { bold: bb } });
      T(s, r, { x: 0.45, y: ys[i], w: 7.4, h: i === 1 ? 0.8 : 0.45, fontFace: 'Arial', fontSize: 20, color: '000000', bullet: true, align: i === 1 ? 'justify' : 'left' });
    });
    s.addImage({ path: path.join(IMG, 'i6.png'), x: 8.7, y: 1.83, w: 3.5, h: 3.74 });
  }

  // ───────────────────── SLIDE 2 — IDEA / SOLUTION ─────────────────────
  {
    const s = pres.addSlide();
    header(s, null);
    s.addImage({ path: path.join(IMG, 'i63.png'), x: 2.28, y: 0.08, w: 0.6, h: 0.63 });
    s.addImage({ path: path.join(IMG, 'i65.png'), x: 2.35, y: 0.15, w: 0.46, h: 0.49 });
    T(s, 'SentiNet : A World Model that Forecasts Network Attacks', { x: 2.95, y: 0.12, w: 8.9, h: 0.55, fontFace: SERIF, bold: true, fontSize: 20, color: NAVY, valign: 'middle' });
    box(s, 0.42, 0.8, 12.5, 0.4, 'EAF1F8', 'B4C7DC');
    T(s, 'Enterprise & Critical Information Infrastructure  |  Learns P(Sₜ₊₁ | Sₜ)  |  K-step attack forecasting  |  MITRE ATT&CK stages  |  SHAP + attention explanations  |  Runs fully offline',
      { x: 0.5, y: 0.8, w: 12.35, h: 0.4, fontFace: SERIF, bold: true, fontSize: 11.5, color: '1B2A3A', align: 'center', valign: 'middle' });

    // left panel — IDEA / SOLUTION
    box(s, 0.3, 1.33, 6.35, 5.27, LBLUE, LBLUE_B, { lw: 1.25 });
    heading(s, 'IDEA / SOLUTION', 0.3, 1.38, 6.35);
    box(s, 0.52, 1.8, 5.93, 0.82, DARK, DARK, { round: 0.06 });
    T(s, [
      { text: 'Intrusion detectors tell you a breach has happened. ' },
      { text: 'SentiNet tells you where the attacker is going next, ', options: { color: YEL } },
      { text: 'while the attacker is still scanning and there is still time to stop them.', options: { underline: { style: 'sng' } } },
    ], { x: 0.64, y: 1.84, w: 5.7, h: 0.74, fontSize: 12.5, bold: true, color: WHITE, valign: 'middle' });

    const ideas = [
      ['chip', 'Learns how the network changes over time', 'A world model learns P(Sₜ₊₁ | Sₜ): how a graph of hosts, flow and packet features changes each minute. It does not just label single flows.'],
      ['fwd', 'Plays the future forward', 'Simulates 64 possible futures up to K windows ahead. The share that reach an infiltration state is the infiltration probability, shown with a confidence band.'],
      ['map', 'Names the next attack stage and target', 'Each forecast maps to MITRE ATT&CK: Reconnaissance → Initial Access → Lateral Movement → C2 → Exfiltration, and names the host likely hit next.'],
      ['why', 'Shows its reasoning', 'Attention weights and SHAP values list the flags, ports and flow statistics behind every forecast. No unexplained scores.'],
      ['whatif', '“What if we block it?”', 'The defender applies an action (block port 445, isolate a host) inside the model and sees how the risk changes, before touching the real network.'],
      ['base', 'A working prototype, not only a plan', 'PCAP or CSV in; forecasts, Shapley explanations, flagged flows and signed receipts out. Offline app, ordinary CPU.'],
    ];
    let y = 2.72;
    const rh = 0.625;
    ideas.forEach(([k, t, d], i) => {
      box(s, 0.52, y, 5.93, rh - 0.05, WHITE, i % 3 === 1 ? '2F4A6E' : 'C9D3E0', { lw: i % 3 === 1 ? 1.5 : 0.75, round: 0.05 });
      s.addShape(pres.shapes.OVAL, { x: 0.62, y: y + 0.1, w: 0.38, h: 0.38, fill: { color: 'D6E0EE' }, line: { color: 'D6E0EE' } });
      s.addImage({ data: ic[k], x: 0.7, y: y + 0.18, w: 0.22, h: 0.22 });
      T(s, t, { x: 1.1, y: y + 0.03, w: 5.25, h: 0.2, fontSize: 11.5, bold: true, color: NAVY2 });
      T(s, d, { x: 1.1, y: y + 0.22, w: 5.28, h: 0.34, fontSize: 9.5, color: BODY });
      y += rh;
    });

    // right top — PROBLEM RESOLUTION
    box(s, 6.82, 1.33, 6.1, 2.3, WHITE, GREYB, { lw: 1, shadow: true });
    heading(s, 'PROBLEM RESOLUTION', 6.82, 1.37, 6.1, { fontSize: 18 });
    T(s, [
      ...lead('Classifiers see flows, not campaigns: ', 'a benign/malicious label per flow throws away order and timing. A slow scan, then a brute-force, then lateral SMB traffic is one story, not three unrelated alerts.', true),
      ...lead('Alerts come after the damage: ', 'detection fires once a stage has already happened. Defenders need the warning while the attacker is still in reconnaissance.', true),
      ...lead('Scores nobody can act on: ', 'a probability with no “why” and no “what next” gets ignored by SOC analysts and cannot be audited in CII.'),
    ], { x: 7.0, y: 1.78, w: 5.8, h: 1.8, fontSize: 11.5, paraSpaceAfter: 4 });

    // right bottom — INNOVATION & UNIQUENESS
    box(s, 6.82, 3.75, 6.1, 2.85, WHITE, GREYB, { lw: 1, shadow: true });
    heading(s, 'INNOVATION & UNIQUENESS', 6.82, 3.79, 6.1, { fontSize: 18 });
    const inn = [
      ['w1', '1E7B4F', 'Attack “weather forecast”', 'Many sampled futures give a risk band and time-to-compromise, not one label.'],
      ['w2', 'B45F06', 'Knows the attacker’s playbook', 'An ATT&CK/CAPEC knowledge base names the technique and its mitigation; CVE exposure raises host risk.'],
      ['w3', '2E75B6', 'Flow + packet, on a graph', 'TTL, window size and port order catch slow scans; the graph predicts which host is next.'],
      ['w4', '7030A0', 'What-if defence simulator', 'Test a block or isolate action inside the model before using it.'],
      ['w5', '1F3B64', 'Auditable forecasts', 'Each forecast is signed into a Merkle ledger and later scored against what actually happened.'],
      ['w6', 'C00000', 'Cheap enough for CII', '~170k parameters: 12 h of traffic forecast in seconds on a laptop CPU, fully offline.'],
    ];
    inn.forEach(([k, c, t, d], i) => {
      const col = i % 2, row = Math.floor(i / 2);
      const x = 6.97 + col * 2.98, yy = 4.22 + row * 0.78;
      s.addShape(pres.shapes.OVAL, { x, y: yy, w: 0.36, h: 0.36, fill: { color: c }, line: { color: c } });
      s.addImage({ data: ic[k], x: x + 0.09, y: yy + 0.09, w: 0.18, h: 0.18 });
      T(s, t, { x: x + 0.44, y: yy - 0.01, w: 2.45, h: 0.22, fontSize: 11, bold: true, color: '1B2A3A' });
      T(s, d, { x: x + 0.44, y: yy + 0.2, w: 2.45, h: 0.52, fontSize: 9, color: MUTED });
    });
    s.addShape(pres.shapes.LINE, { x: 9.87, y: 4.25, w: 0, h: 2.25, line: { color: 'D9D9D9', width: 0.75 } });

    // bottom milestone line
    s.addShape(pres.shapes.LINE, { x: 0.42, y: 6.84, w: 12.5, h: 0, line: { color: 'A0A7B0', width: 1.25 } });
    const ms = [['F4B183', 'Built: flow + packet pipeline', 'PCAP (Scapy) + CIC / CTU-13 / UNSW loaders'], ['2E8B57', 'Built: world model + forecaster', 'K-step rollouts, Shapley, what-if'], ['2E75B6', 'Built: offline demo app', 'Streamlit + CLI + signed receipts'], ['FFD966', 'Next: real-data training', 'CIC-IDS2018, CTU-13, DARPA 2000; CII pilot']];
    ms.forEach(([c, a, b], i) => {
      const cx = 1.95 + i * 3.15;
      s.addShape(pres.shapes.OVAL, { x: cx - 0.09, y: 6.75, w: 0.18, h: 0.18, fill: { color: c }, line: { color: '7F7F7F', width: 0.5 } });
      T(s, a, { x: cx - 1.5, y: 6.97, w: 3.0, h: 0.2, fontSize: 11, bold: true, color: NAVY2, align: 'center' });
      T(s, b, { x: cx - 1.5, y: 7.17, w: 3.0, h: 0.2, fontSize: 9.5, color: BODY, align: 'center' });
    });
  }

  // ───────────────────── SLIDE 3 — TECHNICAL APPROACH ─────────────────────
  {
    const s = pres.addSlide();
    header(s, 'TECHNICAL APPROACH');
    heading(s, 'WORLD MODEL ARCHITECTURE', 0.35, 0.62, 5.9, { fontSize: 17, align: 'left' });
    box(s, 0.3, 1.02, 6.15, 4.08, WHITE, '5B7BA3', { lw: 1 });
    const B = (b, t) => [{ text: b, options: { bold: true, bullet: true } }, { text: t, options: { breakLine: true } }];
    T(s, [
      { text: 'SentiNet learns ' }, { text: 'how network state changes', options: { bold: true } },
      { text: '. An encoder turns each time window into a state, a dynamics model learns ' }, { text: 'P(Sₜ₊₁ | Sₜ)', options: { bold: true } },
      { text: ', and a rollout engine simulates K steps ahead.', options: { breakLine: true } },
      ...B('State Sₜ (every 60 s window): ', 'a graph with hosts as nodes and flows as edges. Flow-level features: TCP flag counts (SYN/ACK/FIN/RST/PSH/URG), bytes, packets, duration, IAT mean/var/max, bidirectional ratio. Packet-level features: TTL mean and variance, TCP window size, fragment flags, payload-size histogram, sequential vs random port order, retransmissions.'),
      ...B('Encoder: ', 'edge-weighted GraphSAGE over the host graph + an MLP on the state vector → one latent vector per window, plus one per host.'),
      ...B('Dynamics (the world model): ', 'recurrent state-space model (GRU memory + stochastic latent) with a causal Temporal Transformer over the last 30 windows. It learns to predict the next state’s features (self-supervised) and the next ATT&CK stage from the datasets’ attack timelines (supervised dynamics learning).'),
      ...B('Forward simulation: ', 'sample 64 latent paths K = 1…10 windows ahead → P(infiltration within K), predicted stage and next target host.'),
      { text: 'Explanations: ', options: { bold: true, bullet: true } }, { text: 'attention over time and neighbours + SHAP over feature groups → e.g. “top drivers: SYN-only ratio ↑, dst-port entropy ↑, TTL variance ↑”.' },
    ], { x: 0.42, y: 1.08, w: 5.93, h: 3.98, fontFace: SERIF, fontSize: 12, color: '000000', paraSpaceAfter: 3 });

    // tech stack
    heading(s, 'SENTINET TECH STACK', 6.6, 0.68, 6.5, { fontSize: 17 });
    const pills = [['Technology', '2F4F4F', WHITE], ['Python 3.11', 'C9E3A6'], ['PyTorch + PyG', 'F3F09B'], ['Scapy / PyShark', 'E9D8B4'], ['CICFlowMeter', 'D9D2E9'], ['SHAP / Captum', 'F4CCCC'], ['ONNX', 'C9DAF8'], ['Streamlit', 'B7E1CD']];
    let px = 6.62;
    pills.forEach(([t, c, fc]) => {
      const w = 0.12 + t.length * 0.05;
      box(s, px, 1.1, w, 0.3, c, '9E9E9E', { round: 0.05, lw: 0.5 });
      T(s, t, { x: px, y: 1.1, w, h: 0.3, fontFace: 'Arial', fontSize: 7.5, color: fc || '333333', align: 'center', valign: 'middle', bold: !!fc });
      px += w + 0.05;
    });

    // pipeline diagram
    heading(s, 'WORLD-MODEL PIPELINE', 6.6, 1.5, 6.5, { fontSize: 17 });
    const node = (x, y, w, h, t, fill, bold = true, fs = 9.5) => {
      box(s, x, y, w, h, fill, '7F8C9C', { round: 0.06, lw: 0.75 });
      T(s, t, { x, y, w, h, fontFace: SANS, fontSize: fs, bold, color: '1B2A3A', align: 'center', valign: 'middle' });
    };
    const arrow = (x1, y1, x2, y2, c = '4A5A70') => s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1), flipH: x2 < x1, flipV: y2 < y1, line: { color: c, width: 1.25, endArrowType: 'triangle' } });
    // row 1
    node(6.62, 1.98, 1.35, 0.62, 'PCAP / CSV\n(CIC-IDS2018, CTU-13)', 'FCE4D6');
    node(8.22, 1.98, 1.5, 0.62, 'Feature extractor\nflow + packet level', 'E7E6E6');
    node(9.97, 1.98, 1.38, 0.62, 'State graph Sₜ\n(60 s window)', 'FFF2CC');
    node(11.6, 1.98, 1.35, 0.62, 'GNN encoder\nGraphSAGE', 'DDEBF7');
    arrow(7.97, 2.29, 8.22, 2.29); arrow(9.72, 2.29, 9.97, 2.29); arrow(11.35, 2.29, 11.6, 2.29);
    // row 2
    node(10.55, 2.95, 2.4, 0.72, 'Latent dynamics\nP(Sₜ₊₁ | Sₜ)\nRSSM + Temporal Transformer', 'D9EAD3');
    arrow(12.27, 2.6, 12.27, 2.95);
    node(6.62, 2.98, 2.1, 0.66, 'What-if action\n(block port / isolate host)', 'F8CBAD', true, 9);
    arrow(8.72, 3.31, 10.55, 3.31);
    T(s, 're-simulate', { x: 8.8, y: 3.06, w: 1.7, h: 0.22, fontSize: 8.5, italic: true, color: MUTED, align: 'center' });
    // row 3
    node(10.55, 4.0, 2.4, 0.62, 'K-step rollout × 64 samples\n(forward simulation)', 'FFE699');
    arrow(11.75, 3.67, 11.75, 4.0);
    node(6.62, 4.0, 2.1, 0.62, 'ATT&CK · CAPEC knowledge\n+ CVE/NVD host exposure', 'EADCF0', true, 9);
    // outputs
    const outs = [['ATT&CK stage, techniques\n+ mitigations, next host', 'BDD7EE'], ['Infiltration probability\nnext K windows', 'C6E0B4'], ['Top drivers\nShapley + attention', 'F4CCCC']];
    outs.forEach(([t, c], i) => node(6.62 + i * 2.12, 4.9, 1.98, 0.55, t, c, true, 9));
    s.addShape(pres.shapes.LINE, { x: 7.95, y: 4.76, w: 3.9, h: 0, line: { color: '4A5A70', width: 1.25 } });
    arrow(11.75, 4.62, 11.75, 4.76);
    [7.95, 9.73, 11.85].forEach(x => arrow(x, 4.76, x, 4.9));
    arrow(7.2, 4.62, 7.2, 4.9, '8E6BB0');
    T(s, 'Every forecast is signed into our Merkle ledger, so it can be checked later against what actually happened.', { x: 6.62, y: 5.5, w: 6.3, h: 0.22, fontSize: 9, italic: true, color: MUTED, align: 'center' });

    // attack-stage chain (replaces tamper-evident trail)
    heading(s, 'FORECAST ATTACK STAGES  (MITRE ATT&CK)', 0.3, 5.2, 6.2, { fontSize: 15 });
    box(s, 0.3, 5.6, 6.15, 1.72, WHITE, '5B7BA3', { lw: 1 });
    const st = [['Reconnais-\nsance', 'T1595 · T1046', 'FCE4D6'], ['Initial\nAccess', 'T1190 · T1110', 'E7E6E6'], ['Lateral\nMovement', 'T1021 · T1570', 'FFE699'], ['Command &\nControl', 'T1071 · T1573', 'BDD7EE'], ['Exfiltration', 'T1041 · T1048', 'C6E0B4']];
    st.forEach(([a, b, c], i) => {
      const x = 0.42 + i * 1.2;
      box(s, x, 5.78, 1.0, 0.78, c, '7F8C9C', { round: 0.08, lw: 0.75 });
      T(s, a, { x, y: 5.8, w: 1.0, h: 0.52, fontSize: 10, bold: true, color: '1B2A3A', align: 'center', valign: 'middle' });
      T(s, b, { x, y: 6.3, w: 1.0, h: 0.22, fontSize: 7.5, color: MUTED, align: 'center' });
      if (i < 4) arrow(x + 1.0, 6.17, x + 1.2, 6.17, '2E75B6');
    });
    T(s, 'Dataset labels (e.g. CIC-IDS2018 “Infiltration”, “Brute Force”, “Bot”; DARPA 2000 LLDOS phases 1–5) are mapped to these stages. The benign → recon → access transitions are the ones the model must learn to see coming.',
      { x: 0.42, y: 6.64, w: 5.95, h: 0.64, fontSize: 9.5, color: BODY });

    box(s, 6.62, 5.8, 6.35, 1.52, WHITE, '7F7F7F', { lw: 1 });
    T(s, [
      { text: 'Supervised dynamics learning: ', options: { bold: true } },
      { text: 'ground-truth transitions come from each dataset’s attack timeline. The loss weights transitions into attack stages, so rare stages are learned. ' },
      { text: 'Output per window: ', options: { bold: true } },
      { text: 'P(infiltration in the next K windows), predicted stage, top contributing flags/ports/flow stats, and the next target host. ' },
      { text: 'Not a static classifier: ', options: { bold: true } },
      { text: 'we show it by shuffling time. If accuracy does not drop, it has not learned dynamics.' },
    ], { x: 6.72, y: 5.85, w: 6.15, h: 1.44, fontFace: SERIF, fontSize: 12.5, color: '000000', align: 'justify' });
  }

  // ───────────────────── SLIDE 4 — FEASIBILITY & VIABILITY ─────────────────────
  {
    const s = pres.addSlide();
    header(s, 'FEASIBILITY & VIABILITY');
    // left peach — challenges + funnel
    box(s, 0.62, 0.78, 9.65, 2.92, PEACH, PEACH_B, { lw: 1 });
    T(s, 'POTENTIAL CHALLENGES AND RISKS:', { x: 0.9, y: 1.08, w: 5.0, h: 0.32, fontFace: SERIF, bold: true, fontSize: 16, color: NAVY, underline: { style: 'sng' } });
    T(s, [
      { text: 'Attack windows are rare: ', options: { bold: true } }, { text: 'attack time is a small fraction of each capture, and stages like exfiltration are rarer still.', options: { breakLine: true } },
      { text: 'Order may carry no signal: ', options: { bold: true } }, { text: 'our earlier project found shuffling time changed nothing. Here we test it on every result: shuffling history drops F1 from 0.865 to 0.347.', options: { breakLine: true } },
      { text: 'Dataset shift: ', options: { bold: true } }, { text: 'a model trained on a lab network may not carry over to a real enterprise or CII network.' },
    ], { x: 0.9, y: 1.5, w: 4.95, h: 2.1, fontFace: SERIF, fontSize: 12.5, color: '000000', paraSpaceAfter: 6 });
    // funnel
    T(s, 'Market Opportunity Funnel', { x: 6.0, y: 0.84, w: 2.6, h: 0.25, fontFace: 'Arial', bold: true, fontSize: 11, color: '000000', align: 'center' });
    s.addShape(pres.shapes.OVAL, { x: 6.1, y: 1.14, w: 2.4, h: 2.4, fill: { color: 'D4E157' }, line: { color: 'AFB42B', width: 1 } });
    s.addShape(pres.shapes.OVAL, { x: 6.45, y: 1.62, w: 1.9, h: 1.9, fill: { color: 'AED581' }, line: { color: '7CB342', width: 1 } });
    s.addShape(pres.shapes.OVAL, { x: 6.78, y: 2.12, w: 1.4, h: 1.4, fill: { color: 'F4A460' }, line: { color: 'E08A3C', width: 1 } });
    T(s, '$7.96 Bn', { x: 6.1, y: 1.28, w: 2.4, h: 0.25, fontSize: 9.5, bold: true, color: '5D6D00', align: 'center' });
    T(s, '$878 Mn', { x: 6.45, y: 1.78, w: 1.9, h: 0.25, fontSize: 9.5, bold: true, color: 'C2185B', align: 'center' });
    T(s, '≈ $26 Mn', { x: 6.78, y: 2.65, w: 1.4, h: 0.3, fontSize: 10.5, bold: true, color: '3E2723', align: 'center' });
    T(s, [
      { text: 'TAM  $7.96 Bn', options: { bold: true, fontSize: 12, color: '7030A0', breakLine: true } },
      { text: 'Global Intrusion Detection & Prevention market, 2026 (Precedence Research)', options: { fontSize: 9, breakLine: true } },
      { text: ' ', options: { fontSize: 5, breakLine: true } },
      { text: 'SAM  up to $878 Mn', options: { bold: true, fontSize: 12, color: 'C00000', breakLine: true } },
      { text: 'India OT security market, 2026 (MarketsandMarkets)', options: { fontSize: 9, breakLine: true } },
      { text: ' ', options: { fontSize: 5, breakLine: true } },
      { text: 'SOM  ≈ $26 Mn', options: { bold: true, fontSize: 12, color: '000000', breakLine: true } },
      { text: 'We aim for 3% of the available market: SOCs that want early warning, not only alerts.', options: { fontSize: 9 } },
    ], { x: 8.62, y: 1.05, w: 1.58, h: 2.6, fontFace: SERIF, color: '000000' });

    // right peach — strategies
    box(s, 10.42, 0.78, 2.55, 5.05, PEACH, PEACH_B, { lw: 1 });
    T(s, 'STRATEGIES TO OVERCOME THESE CHALLENGES:', { x: 10.52, y: 0.9, w: 2.38, h: 0.62, fontFace: SERIF, bold: true, fontSize: 13, color: OLIVE, underline: { style: 'sng' } });
    T(s, [
      { text: 'Weight the rare stages: ', options: { bold: true, bullet: true } }, { text: 'focal loss, oversampling of attack transitions, training on several datasets (CIC-IDS2018, CTU-13, UNSW-NB15, CICIoT2023).', options: { breakLine: true } },
      { text: 'Prove the time effect: ', options: { bold: true, bullet: true } }, { text: 'every result is shown next to logistic regression on the same features and next to our model with time shuffled. If there is no gap, we say so.', options: { breakLine: true } },
      { text: 'No-leak, unseen-attack tests: ', options: { bold: true, bullet: true } }, { text: 'split by time, never by random row. Hold out whole attack families and whole datasets. Fine-tune per site on ~10 days of its own benign traffic.' },
    ], { x: 10.52, y: 1.58, w: 2.38, h: 4.2, fontFace: SERIF, fontSize: 12, color: '000000', paraSpaceAfter: 6 });

    // evaluation plan table
    const hd = (t) => ({ text: t, options: { bold: true, color: '000000', fill: { color: WHITE } } });
    const c1 = (t) => ({ text: t, options: { bold: true, color: NAVY2 } });
    const rows = [
      [hd('Component'), hd('Trained / tested on'), hd('What we will report')],
      [c1('Feature pipeline · Scapy + CICFlowMeter'), 'CIC-IDS2018 CSV + PCAP, CTU-13', 'Timestamped, normalised flow + packet matrix; flows/s'],
      [c1('World model · RSSM + Transformer + GNN'), 'CIC-IDS2018, CTU-13, UNSW-NB15', 'Next-state error; stage F1 at t+1…t+K'],
      [c1('Forecast engine · K-step rollout'), 'DARPA 2000 LLDOS, LANL red team', 'Lead time before compromise; AUC@K; Brier score'],
      [c1('Baseline · Logistic regression'), 'Same features, same time split', 'F1, precision, recall, FPR, side by side'],
      [c1('Generalisation'), 'Leave-one-attack-out; CICIoT2023', 'Recall on attack types never seen in training'],
      [c1('Explainer · SHAP + attention'), 'All of the above', 'Deletion test: remove top-5 drivers → risk must fall'],
    ];
    s.addTable(rows, { x: 0.62, y: 3.83, w: 9.65, colW: [3.25, 2.9, 3.5], fontFace: SERIF, fontSize: 10.5, color: '000000', border: { type: 'solid', color: '4472C4', pt: 1 }, rowH: 0.27, valign: 'middle', margin: [0.02, 0.06, 0.02, 0.06] });
    T(s, '*Current scores are on held-out simulated scenarios (bundled simulator). This table is the real-data plan.', { x: 10.42, y: 5.9, w: 2.55, h: 0.42, fontFace: SERIF, italic: true, bold: true, fontSize: 8, color: '404040' });

    // proof it runs today
    T(s, 'PROOF IT RUNS TODAY:', { x: 0.62, y: 5.95, w: 6, h: 0.35, fontFace: SERIF, bold: true, fontSize: 17, color: NAVY, underline: { style: 'sng' } });
    const proofs = [
      ['Runs on a laptop CPU: ', '12 h of traffic (67,650 flows) forecast in ~2 s: 720 windows x 64 simulated futures.'],
      ['PCAP in, offline: ', 'a 441k-packet PCAP parsed into flow + packet features in 2.7 s. No GPU, no cloud.'],
      ['Beats the baseline: ', 'F1 0.865 vs 0.483 (logistic regression) at the same 3.1% false-positive rate.*'],
      ['Tested: ', '28 automated tests: loaders, PCAP round-trip, Shapley efficiency, tamper detection.'],
    ];
    proofs.forEach(([a, b], i) => {
      const x = 0.62 + i * 3.1;
      box(s, x, 6.42, 2.95, 0.8, 'FDF3EE', 'C0504D', { lw: 0.75 });
      T(s, [{ text: a, options: { bold: true, color: 'C00000' } }, { text: b }], { x: x + 0.08, y: 6.46, w: 2.8, h: 0.74, fontFace: SERIF, fontSize: 11.5, color: '000000' });
    });
  }

  // ───────────────────── SLIDE 5 — IMPACT & BENEFITS ─────────────────────
  {
    const s = pres.addSlide();
    header(s, 'IMPACT & BENEFITS');
    box(s, 0.3, 0.6, 6.45, 3.12, WHITE, GREYB, { lw: 1 });
    heading(s, 'SENTINET VS. EXISTING TOOLS', 0.3, 0.63, 6.45, { fontSize: 16 });
    const G = '2E7D32', R = 'C00000';
    const hc = (t) => ({ text: t, options: { bold: true, color: '1B2A3A', fill: { color: WHITE }, align: 'center' } });
    const cell = (t, c = BODY, b = false, fill) => ({ text: t, options: Object.assign({ color: c, bold: b, align: 'center' }, fill ? { fill: { color: fill } } : {}) });
    const NS = 'EAF1F8';
    const rows = [
      [{ text: 'Capability', options: { bold: true, color: '1B2A3A', fill: { color: WHITE } } }, hc('Forecasts next stage'), hc('Learns time dynamics'), hc('ATT&CK stage mapping'), hc('Explains each output'), hc('Works offline')],
      [{ text: 'SentiNet', options: { bold: true, color: NAVY2, fontSize: 10, fill: { color: NS } } }, cell('Yes: K-step probability', G, true, NS), cell('Yes: world model', G, true, NS), cell('Yes, per forecast', G, true, NS), cell('Yes: SHAP + attention', G, true, NS), cell('Yes', G, true, NS)],
      [{ text: 'Snort / Suricata', options: { bold: true } }, cell('No', R, true), cell('No: rules', R, true), cell('Partial (rule tags)'), cell('Rule name only'), cell('Yes', G)],
      [{ text: 'ML flow classifiers (RF / XGBoost IDS)', options: { bold: true } }, cell('No', R, true), cell('No: one flow at a time', R, true), cell('No'), cell('Sometimes'), cell('Yes', G)],
      [{ text: 'Commercial NDR / SIEM (e.g. Darktrace, Splunk)', options: { bold: true } }, cell('Risk scores, not stage forecasts'), cell('Varies'), cell('Yes', G), cell('Partial'), cell('Varies: often cloud')],
    ];
    s.addTable(rows, { x: 0.38, y: 1.02, w: 6.3, colW: [1.5, 0.98, 0.98, 0.94, 0.95, 0.95], fontFace: SANS, fontSize: 8.5, color: BODY, valign: 'middle', border: { type: 'solid', color: 'D9D9D9', pt: 0.75 }, rowH: [0.42, 0.5, 0.4, 0.5, 0.5], margin: [0.02, 0.03, 0.02, 0.03] });

    // IMPACTS
    box(s, 0.3, 3.82, 6.45, 3.55, LBLUE, LBLUE_B, { lw: 1.25 });
    heading(s, 'IMPACTS', 0.3, 3.84, 6.45, { fontSize: 16 });
    box(s, 0.42, 4.2, 6.2, 0.6, DARK, DARK);
    T(s, [{ text: 'The blind spot: ', options: { bold: true, color: YEL } }, { text: 'SOCs protecting India’s power, banking, telecom and government networks see an attack only after a stage completes, and CERT-In’s 6-hour reporting clock starts after the damage is done.' }],
      { x: 0.5, y: 4.22, w: 6.05, h: 0.56, fontSize: 10.5, color: WHITE, valign: 'middle' });
    const imp = [
      ['What changes: ', 'a forecast minutes to hours ahead, naming the next stage and the host likely hit next.'],
      ['For operators: ', 'an early warning while the attacker is still scanning.'],
      ['For analysts: ', 'one forecast carrying the whole chain and its drivers, not scattered alerts.'],
      ['For auditors: ', 'every forecast is signed and later checked against reality, so accuracy itself is auditable.'],
      ['For the nation: ', 'runs inside the premises of NCIIPC-notified CII. No traffic data leaves the site.'],
      ['Beyond this: ', 'hospitals, rail signalling, smart grids and IoT (tested on CICIoT2023).'],
    ];
    imp.forEach(([a, b], i) => {
      const y = 4.86 + i * 0.41;
      box(s, 0.42, y, 6.2, 0.36, WHITE, 'C9D3E0', { lw: 0.75 });
      T(s, [{ text: a, options: { bold: true, color: 'C00000' } }, { text: b }], { x: 0.5, y, w: 6.08, h: 0.36, fontSize: 10.5, color: '1B2A3A', valign: 'middle' });
    });

    // USE CASES
    box(s, 6.88, 0.6, 6.1, 3.12, WHITE, GREYB, { lw: 1 });
    heading(s, 'USE CASES', 6.88, 0.63, 6.1, { fontSize: 18 });
    const uc = [
      ['ind', 'E07B53', 'Power & Energy Grid (CII)', 'Forecasts recon → lateral movement towards SCADA hosts before control is reached.'],
      ['gov', '1E9BE9', 'Government SOC & CERT-In', 'ATT&CK-mapped forecasts and signed evidence fit the 6-hour reporting rule.'],
      ['bank', 'F2B134', 'Banking & Finance', 'Predicts brute-force → access → exfiltration and names the server at risk.'],
      ['edu', '9B59B6', 'Enterprises, MSMEs & Colleges', 'CPU-only, offline, one SPAN port: early warning they can afford.'],
    ];
    uc.forEach(([k, c, t, d], i) => {
      const x = 7.0 + (i % 2) * 2.95, y = 1.03 + Math.floor(i / 2) * 1.32;
      box(s, x, y, 2.83, 1.22, c, c, { round: 0.06 });
      s.addImage({ data: ic[k], x: x + 0.1, y: y + 0.1, w: 0.24, h: 0.24 });
      T(s, t, { x: x + 0.4, y: y + 0.05, w: 2.38, h: 0.36, fontFace: SERIF, fontSize: 12, bold: true, color: '1B1B1B', align: 'center', valign: 'middle' });
      T(s, d, { x: x + 0.1, y: y + 0.44, w: 2.65, h: 0.74, fontSize: 11.5, color: i === 2 ? '1B1B1B' : WHITE });
    });

    // benefits
    box(s, 6.88, 3.82, 6.1, 3.55, WHITE, GREYB, { lw: 1 });
    const cols = [
      ['lock', 'Security Benefits', 'CFE0DC', [['Act before compromise: ', 'block, isolate or watch while the attacker is still in recon.'], ['Knows the next target: ', 'response is focused on the host most likely hit next.'], ['Catches the unseen: ', 'judges stage behaviour, not signatures.']]],
      ['coins', 'Economic Benefits', 'F4CFC6', [['Cheaper to stop early: ', 'containing at recon costs far less than cleaning up a breach.'], ['Low hardware cost: ', 'one CPU box per segment, no GPU, no licence fees.'], ['Less alert fatigue: ', 'one forecast per campaign, not dozens of alerts.']]],
      ['cogs', 'Technical Benefits', 'D5E3E0', [['Offline & open source: ', 'code, weights and training configs included, reproducible.'], ['Two levels of traffic: ', 'flow + packet features fused on a graph.'], ['What-if simulation: ', 'try a defensive action in the model first.']]],
    ];
    cols.forEach(([k, t, c, items], i) => {
      const x = 6.98 + i * 2.0;
      box(s, x, 3.93, 1.9, 3.34, c, c, { round: 0.06 });
      s.addImage({ data: ic[k], x: x + 0.1, y: 4.06, w: 0.2, h: 0.2 });
      T(s, t, { x: x + 0.33, y: 4.01, w: 1.55, h: 0.3, fontSize: 11.5, bold: true, color: '262626', valign: 'middle' });
      const runs = [];
      items.forEach(([a, b], j) => { runs.push({ text: a, options: { bold: true } }); runs.push({ text: b, options: { breakLine: j < items.length - 1 } }); });
      T(s, runs, { x: x + 0.1, y: 4.4, w: 1.72, h: 2.82, fontSize: 11, color: '262626', paraSpaceAfter: 8 });
    });
  }

  // ───────────────────── SLIDE 6 — RESEARCH & REFERENCES ─────────────────────
  {
    const s = pres.addSlide();
    header(s, 'RESEARCH & REFERENCES');
    // citations
    box(s, 0.25, 0.6, 3.35, 4.25, 'DFE6F2', LBLUE_B, { lw: 1 });
    heading(s, 'CITATIONS', 0.25, 0.66, 3.35, { fontSize: 16 });
    const cites = [
      ['World Models', 'Ha & Schmidhuber, 2018', 'Learn an internal model, then roll it forward.'],
      ['Latent Dynamics (RSSM)', 'Hafner et al., DreamerV3, 2023', 'The recurrent state-space model we adapt to network state.'],
      ['Graph NIDS', 'Lo et al., E-GraphSAGE, IEEE NOMS 2022', 'Flows as graph edges; basis of our encoder.'],
      ['Attack Forecasting', 'Husák et al., IEEE COMST 2019', 'Survey of attack projection, prediction & forecasting.'],
      ['Explainability', 'Lundberg & Lee, NeurIPS 2017 (SHAP)', 'Feature attribution for every forecast.'],
    ];
    cites.forEach(([a, b, c], i) => {
      const y = 1.04 + i * 0.75;
      box(s, 0.35, y, 3.15, 0.69, WHITE, 'C9D3E0', { round: 0.06, lw: 0.75 });
      box(s, 0.45, y + 0.04, 1.75, 0.2, DARK, DARK, { round: 0.1 });
      T(s, a, { x: 0.45, y: y + 0.04, w: 1.75, h: 0.2, fontSize: 9, bold: true, color: WHITE, align: 'center', valign: 'middle' });
      T(s, b, { x: 0.45, y: y + 0.26, w: 3.0, h: 0.18, fontSize: 9.5, bold: true, color: '1B2A3A' });
      T(s, c, { x: 0.45, y: y + 0.45, w: 3.0, h: 0.2, fontSize: 8.5, color: BODY });
    });
    // links
    box(s, 0.25, 4.95, 3.35, 2.45, 'EDEFF2', GREYB, { lw: 1 });
    T(s, [{ text: 'LINKS ', options: { fontSize: 15, underline: { style: 'sng' } } }, { text: '(Ctrl + Click on the blue words)', options: { fontSize: 10 } }], { x: 0.35, y: 5.0, w: 3.2, h: 0.32, fontFace: SERIF, bold: true, color: NAVY, valign: 'middle' });
    const links = [
      ['yt', 'Demo Video - Prototype', 'https://github.com/Daryl-69/SentiNet#1-run-it-from-the-downloaded-zip'],
      ['gh', 'GitHub Repository', 'https://github.com/Daryl-69/SentiNet'],
      ['wd', 'Documentation', 'https://github.com/Daryl-69/SentiNet/blob/main/docs/ARCHITECTURE.md'],
      ['pp', 'Presentation', 'https://github.com/Daryl-69/SentiNet/tree/main/ppt'],
    ];
    links.forEach(([k, t, u], i) => {
      const y = 5.4 + i * 0.49;
      box(s, 0.38, y, 3.1, 0.42, WHITE, 'D0D4DA', { round: 0.05, lw: 0.75 });
      s.addImage({ data: ic[k], x: 0.48, y: y + 0.07, w: 0.28, h: 0.28 });
      T(s, t, { x: 0.9, y, w: 2.5, h: 0.42, fontSize: 12, bold: true, color: '1F5FAF', valign: 'middle', hyperlink: { url: u } });
    });

    // standards & knowledge alignment
    box(s, 3.72, 0.6, 5.05, 3.95, WHITE, GREYB, { lw: 1 });
    T(s, 'SentiNet · Standards & Knowledge Alignment', { x: 3.72, y: 0.66, w: 5.05, h: 0.26, fontSize: 11, bold: true, color: '333333', align: 'center' });
    const std = [
      ['MITRE ATT&CK', 'Stage labels + technique IDs for every forecast (T1595, T1190, T1021, T1071, T1041…).', 'DDEBF7'],
      ['CAPEC', 'Attack patterns linked to every ATT&CK technique the evidence points to.', 'E2EFDA'],
      ['CVE / NVD', 'CVSS exposure of each host’s open services raises its chance of being next.', 'FFF2CC'],
      ['NCIIPC · CII', 'Design fits NCIIPC guidance for protected systems: on-prem, passive, no data leaves.', 'FCE4D6'],
      ['CERT-In', 'ATT&CK-mapped, signed forecasts support the 6-hour incident reporting rule.', 'EADCF0'],
      ['RFC 6962', 'Merkle transparency log (as used for web certificates) for tamper-evident forecast receipts.', 'E7E6E6'],
    ];
    std.forEach(([a, b, c], i) => {
      const x = 3.83 + (i % 2) * 2.45, y = 1.0 + Math.floor(i / 2) * 1.17;
      box(s, x, y, 2.35, 1.07, c, 'A6B4C8', { round: 0.06, lw: 0.75 });
      T(s, a, { x: x + 0.08, y: y + 0.05, w: 2.2, h: 0.24, fontSize: 11, bold: true, color: '1F5FAF' });
      T(s, b, { x: x + 0.08, y: y + 0.3, w: 2.2, h: 0.74, fontSize: 9, color: '33405C' });
    });

    // datasets
    box(s, 3.72, 4.65, 5.05, 2.75, 'DFE6F2', LBLUE_B, { lw: 1 });
    heading(s, 'DATASET IMPLEMENTATION', 3.72, 4.68, 5.05, { fontSize: 15 });
    const ds = [
      ['1. CIC-IDS2017/2018: flows + PCAP, day-wise attack timelines', true],
      ['2. CTU-13: 13 botnet scenarios, labelled NetFlow + PCAP', false],
      ['3. UNSW-NB15: 9 attack families, PCAP + flows', false],
      ['4. CICIoT2023: 33 IoT attacks (unseen-attack tests)', false],
      ['5. DARPA 2000 LLDOS 1.0/2.0: 5-phase multi-stage attack', true],
      ['6. LANL auth + red team: real lateral movement, 58 days', false],
      ['7. MITRE ATT&CK · CAPEC · CVE/NVD: knowledge base', false],
      ['8. Own capture, IPv4 + IPv6: benign baseline (already collected)', false],
    ];
    ds.forEach(([t, dark], i) => {
      const y = 5.05 + i * 0.29;
      box(s, 3.82, y, 4.85, 0.26, dark ? DARK : WHITE, dark ? DARK : 'C9D3E0', { lw: 0.5 });
      T(s, t, { x: 3.9, y, w: 4.75, h: 0.26, fontSize: 9.5, bold: true, color: dark ? WHITE : NAVY2, valign: 'middle' });
    });

    // model selection
    box(s, 8.9, 0.6, 4.1, 6.8, WHITE, GREYB, { lw: 1 });
    T(s, 'MODEL SELECTION —\nHEAD-TO-HEAD', { x: 8.95, y: 0.66, w: 4.0, h: 0.55, fontFace: SERIF, bold: true, fontSize: 15, color: NAVY, underline: { style: 'sng' }, align: 'center', valign: 'middle' });
    const th = (t) => ({ text: t, options: { bold: true, color: NAVY2, fontFace: SERIF } });
    const nm = (t) => ({ text: t, options: { bold: true, color: NAVY2, fontFace: SERIF } });
    const pass = (a, b) => [{ text: a, options: { bold: true, color: '7F6000' } }, { text: b }];
    const rows = [
      [th('Component'), th('Compared against'), th('Pass condition')],
      [nm('World model · RSSM + Transformer'), 'Logistic regression; same model with history shuffled', { text: pass('Done*: ', 'F1 0.865 vs 0.483 at equal FPR; shuffled history drops to 0.347') }],
      [nm('Graph encoder · GraphSAGE'), 'Flat feature vector', { text: pass('Better next-target ', 'accuracy from who-talks-to-whom') }],
      [nm('Rollout · 64 samples'), 'Single one-step prediction', { text: pass('Calibrated ', 'probabilities (Brier / ECE)') }],
      [nm('Explainer'), 'Attention only · SHAP · Integrated Gradients', { text: pass('Faithful: ', 'removing top drivers drops the risk') }],
      [nm('ATT&CK / CAPEC knowledge'), 'Stage label only', { text: pass('Actionable: ', 'each alarm names technique, CAPEC pattern and mitigation') }],
    ];
    s.addTable(rows, { x: 9.0, y: 1.3, w: 3.9, colW: [1.15, 1.25, 1.5], fontFace: SANS, fontSize: 10.5, color: '1B2A3A', valign: 'middle', border: [{ type: 'none' }, { type: 'none' }, { type: 'solid', color: 'D9D9D9', pt: 0.75 }, { type: 'none' }], rowH: [0.4, 1.2, 0.95, 0.85, 1.0, 0.9] });
    T(s, '*Measured on held-out simulated scenarios (results/benchmark.md). Other rows: planned, same features and time split, published win or lose.', { x: 9.02, y: 6.75, w: 3.9, h: 0.55, fontFace: SERIF, fontSize: 9.5, color: '595959' });
  }

  await pres.writeFile({ fileName: OUT });
  // pptxgenjs emits one <a:pPr> per run; only the first in a paragraph is valid — drop the rest
  const JSZip = require('jszip');
  const fs = require('fs');
  const zip = await JSZip.loadAsync(fs.readFileSync(OUT));
  const PPR = /<a:pPr\b[^>]*?(?:\/>|>[\s\S]*?<\/a:pPr>)/g;
  let fixed = 0;
  for (const name of Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))) {
    let xml = await zip.file(name).async('string');
    xml = xml.replace(/<a:p>[\s\S]*?<\/a:p>/g, para => {
      let n = 0;
      return para.replace(PPR, m => (n++ === 0 ? m : (fixed++, '')));
    });
    zip.file(name, xml);
  }
  fs.writeFileSync(OUT, await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }));
  console.log('wrote', OUT, 'removed stray pPr:', fixed);
})();
