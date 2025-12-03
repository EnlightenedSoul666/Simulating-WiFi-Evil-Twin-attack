// server.js - FIXED VERSION: Correct strategy costs + working sensitivity toggle
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const {
  genEd25519, genX25519,
  signEd25519, verifyEd25519,
  deriveSharedX25519, hkdf,
  encryptGCM, decryptGCM
} = require('./shared/crypto');

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const PORT = cfg.port || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.static(path.join(__dirname, 'public')));

let tsTolSecs = cfg.timestampToleranceSecs || 60;
const now = () => Date.now() + (cfg.serverClockSkewSecs||0)*1000;

// ============= GAME THEORY FRAMEWORK =============

const PAYOFF_MATRICES = {
  non: {
    TRUST_COOPERATE:   { device: 10,  ap: 5,   cost: 1.0 },
    TRUST_DEFECT:      { device: -50, ap: 40,  cost: 45.0 },
    VERIFY_COOPERATE:  { device: 8,   ap: 4,   cost: 1.4 },
    VERIFY_DEFECT:     { device: -5,  ap: -10, cost: 2.5 },
    AVOID_COOPERATE:   { device: 3,   ap: -2,  cost: 3.2 },
    AVOID_DEFECT:      { device: 5,   ap: -5,  cost: 4.0 }
  },
  sensitive: {
    TRUST_COOPERATE:   { device: 9,    ap: 5,   cost: 1.2 },
    TRUST_DEFECT:      { device: -120, ap: 60,  cost: 120.0 },
    VERIFY_COOPERATE:  { device: 7,    ap: 4,   cost: 1.8 },
    VERIFY_DEFECT:     { device: -20,  ap: -15, cost: 4.0 },
    AVOID_COOPERATE:   { device: 2,    ap: -3,  cost: 4.5 },
    AVOID_DEFECT:      { device: 4,    ap: -7,  cost: 7.0 }
  }
};

let DATA_SENSITIVITY = 'non';
let PAYOFF_MATRIX = PAYOFF_MATRICES[DATA_SENSITIVITY];

const RISK_PARAMS = {
  non:       { alpha: 1.0, beta: 1.3, tail:  8 },
  sensitive: { alpha: 2.0, beta: 1.6, tail: 16 }
};

const SENSITIVITY = {
  non:       { lambda: 0.035, breachPenalty: 35, verifyMitigation: 0.90 },
  sensitive: { lambda: 0.080, breachPenalty: 75, verifyMitigation: 0.95 }
};

const AP_EMA_COST = new Map();

class BayesianAPDetector {
  constructor(apId) {
    this.apId = apId;
    this.priorEvil = 0.25;
    this.observations = [];
    this.posteriorEvil = this.priorEvil;

    this.P_failure_given_evil = 0.85;
    this.P_failure_given_legitimate = 0.15;
    this.P_success_given_evil = 0.15;
    this.P_success_given_legitimate = 0.85;

    // Sliding-window / per-packet update
    this.observations = []; // keep recent booleans + timestamps
    this.batchSize = 100;   // used only to show UI progress
    this.failureCount = 0;  // kept for UI compatibility
    this.successCount = 0;  // kept for UI compatibility

    // Log-odds form for stable per-packet updates with light forgetting
    this.logOdds = Math.log(this.priorEvil / (1 - this.priorEvil));
    this.lastUpdateAt = Date.now();
  }

  
  observePacket(success) {
    // record into sliding window for UI/analytics
    this.observations.push({ success, timestamp: Date.now() });
    if (this.observations.length > this.batchSize) this.observations.shift();
    // maintain legacy counters for compatibility
    if (success) this.successCount++; else this.failureCount++;

    // compute per-packet log-odds update with light forgetting
    const lr = success
      ? (this.P_success_given_evil / this.P_success_given_legitimate)
      : (this.P_failure_given_evil / this.P_failure_given_legitimate);
    const t = Date.now();
    const dt = (t - this.lastUpdateAt) / 1000;
    const decay = Math.exp(-dt / 30); // ~30s time constant
    this.logOdds *= decay;
    this.logOdds += Math.log(lr);
    this.lastUpdateAt = t;
    this.posteriorEvil = 1 / (1 + Math.exp(-this.logOdds));
    this.posteriorEvil = Math.max(0.001, Math.min(0.999, this.posteriorEvil));
  }
  
  isLikelyEvil(threshold = 0.2) {
    return this.posteriorEvil > threshold;
  }
  
  getConfidence() {
    return Math.abs(this.posteriorEvil - 0.5) * 2;
  }
  
  getBufferProgress() {
    const total = this.observations.length;
    return { current: total, target: this.batchSize, percentage: (total / this.batchSize) * 100 };
  }
}

class NashEquilibriumRouter {
  constructor() {
    this.strategyHistory = new Map();
  }
  
  computeOptimalStrategy(apBeliefs) {
    const strategies = {};
    
    for (const [apId, evilProb] of Object.entries(apBeliefs)) {
      const trustExpected = 
        (1 - evilProb) * PAYOFF_MATRIX.TRUST_COOPERATE.device +
        evilProb * PAYOFF_MATRIX.TRUST_DEFECT.device;
      
      const verifyExpected = 
        (1 - evilProb) * PAYOFF_MATRIX.VERIFY_COOPERATE.device +
        evilProb * PAYOFF_MATRIX.VERIFY_DEFECT.device;
      
      const avoidExpected = 
        (1 - evilProb) * PAYOFF_MATRIX.AVOID_COOPERATE.device +
        evilProb * PAYOFF_MATRIX.AVOID_DEFECT.device;
      
      const maxExpected = Math.max(trustExpected, verifyExpected, avoidExpected);
      
      let strategy;
      if (verifyExpected === maxExpected) {
        strategy = 'VERIFY';
      } else if (avoidExpected === maxExpected) {
        strategy = 'AVOID';
      } else {
        strategy = 'TRUST';
      }
      
      strategies[apId] = {
        strategy,
        evilProb,
        expectedPayoffs: { trustExpected, verifyExpected, avoidExpected }
      };
    }
    
    return strategies;
  }
}

// ============= WORLD STATE =============
const LEGITIMATE_APS = {};
const EVIL_APS = {};
const GUEST_APS = {};
const DEVICES = {};
const DETECTORS = new Map();
const NASH_ROUTER = new NashEquilibriumRouter();
const AVOIDED_APS = new Set();

const STATS = { 
  totalSent: 0, totalDelivered: 0, dropped: 0, 
  costWithAP: 0, costWithoutAP: 0,
  spoofersSpawned: 0, spoofersDetected: 0,
  evilAPsDetectedCorrectly: 0,
  guestAPsSpawned: 0,
  evilGuestAPsSpawned: 0,
  packetsAvoided: 0
};

// Rolling cost metrics for charts
let costSinceLastTick = 0;
STATS.cumulativeCost = 0;


// ===== Strategy Scheduler =====
const STRATEGIES = ['TRUST','VERIFY','AVOID'];
let STRAT_IDX = 0;
let ACTIVE_STRATEGY = STRATEGIES[STRAT_IDX];
const STRATEGY_WINDOW_MS = 30000;
const STRATEGY_WINDOW_SECS = STRATEGY_WINDOW_MS / 1000;
let MODE_ENDS_AT = Date.now() + STRATEGY_WINDOW_MS;
const PER_MODE = {
  TRUST:  { sent:0, delivered:0, dropped:0, cost:0 },
  VERIFY: { sent:0, delivered:0, dropped:0, cost:0 },
  AVOID:  { sent:0, delivered:0, dropped:0, cost:0 }
};

setInterval(() => {
  STRAT_IDX = (STRAT_IDX + 1) % STRATEGIES.length;
  ACTIVE_STRATEGY = STRATEGIES[STRAT_IDX];
  MODE_ENDS_AT = Date.now() + STRATEGY_WINDOW_MS;
  console.log(`🔄 Strategy switched to: ${ACTIVE_STRATEGY}`);
  io.emit('strategyMode', { mode: ACTIVE_STRATEGY, endsAt: MODE_ENDS_AT });
}, STRATEGY_WINDOW_MS);

const SPOOF_CONFIG = {
  enabled: true,
  spawnIntervalMs: 15000,
  guestAPsPerSpawn: 4,
  evilProbability: 0.40,
  despawnAfterMs: 60000,
  spawnProbability: 1.0,
  offsetDistance: 120
};

function makeAP(name, x, y, isLegitimate = true, isGuest = false) {
  const ed = genEd25519();
  const xk = genX25519();
  
  const ap = {
    bssid: name,
    pos: { x, y },
    sign: { pub: ed.publicKey, priv: ed.privateKey },
    kex:  { pub: xk.publicKey, priv: xk.privateKey },
    isLegitimate,
    isGuest,
    spawnTime: now(),
    replay: new Set(),
    load: 0,
    capacity: 100,
    signalStrength: isLegitimate ? 100 : 120
  };
  
  if (isGuest) {
    GUEST_APS[name] = ap;
    STATS.guestAPsSpawned++;
    if (!isLegitimate) {
      EVIL_APS[name] = ap;
      STATS.evilGuestAPsSpawned++;
      console.log(`🚨 [EVIL GUEST AP] ${name} at (${x}, ${y})`);
    } else {
      console.log(`✅ [GOOD GUEST AP] ${name} at (${x}, ${y})`);
    }
  } else if (isLegitimate) {
    LEGITIMATE_APS[name] = ap;
  } else {
    EVIL_APS[name] = ap;
    STATS.spoofersSpawned++;
    console.log(`🚨 [ATTACKER SPAWNED] ${name} at (${x}, ${y})`);
  }
  
  DETECTORS.set(name, new BayesianAPDetector(name));
  
  return ap;
}

makeAP('AP1', 150, 150, true);
makeAP('AP2', 500, 150, true);
makeAP('AP3', 850, 150, true);
makeAP('AP4', 150, 400, true);
makeAP('AP5', 500, 400, true);
makeAP('AP6', 850, 400, true);

function spawnGuestAPs() {
  if (!SPOOF_CONFIG.enabled) return;
  
  const legitKeys = Object.keys(LEGITIMATE_APS);
  if (legitKeys.length === 0) return;
  
  for (let i = 0; i < SPOOF_CONFIG.guestAPsPerSpawn; i++) {
    const targetAP = LEGITIMATE_APS[legitKeys[Math.floor(Math.random() * legitKeys.length)]];
    
    const angle = (Math.random() * Math.PI * 2);
    const offset = SPOOF_CONFIG.offsetDistance + (Math.random() * 60);
    const x = Math.max(50, Math.min(950, targetAP.pos.x + Math.cos(angle) * offset));
    const y = Math.max(50, Math.min(550, targetAP.pos.y + Math.sin(angle) * offset));
    
    const isEvil = Math.random() < SPOOF_CONFIG.evilProbability;
    const isLegitimate = !isEvil;
    
    const guestId = `${targetAP.bssid}_guest_${Date.now().toString(36).slice(-4)}_${i}`;
    
    const guestAP = makeAP(guestId, x, y, isLegitimate, true);
    
    setTimeout(() => despawnGuestAP(guestId), SPOOF_CONFIG.despawnAfterMs);
    
    io.emit('guestAPSpawned', {
      bssid: guestId,
      pos: guestAP.pos,
      mimicking: targetAP.bssid,
      isEvil: isEvil
    });
  }
}

function despawnGuestAP(bssid) {
  if (GUEST_APS[bssid]) {
    const wasEvil = !GUEST_APS[bssid].isLegitimate;
    console.log(`♻️ [GUEST AP DESPAWNED] ${bssid} (${wasEvil ? 'evil' : 'good'})`);
    delete GUEST_APS[bssid];
    if (EVIL_APS[bssid]) {
      delete EVIL_APS[bssid];
    }
    DETECTORS.delete(bssid);
    AVOIDED_APS.delete(bssid);
    io.emit('guestAPDespawned', { bssid });
  }
}

setInterval(spawnGuestAPs, SPOOF_CONFIG.spawnIntervalMs);

function getAllAPs() {
  return { ...LEGITIMATE_APS, ...EVIL_APS, ...GUEST_APS };
}

function getTrustedRepo() {
  const repo = {};
  Object.values(LEGITIMATE_APS).forEach(ap => {
    repo[ap.bssid] = { 
      bssid: ap.bssid, 
      ed25519Pub: ap.sign.pub, 
      x25519Pub: ap.kex.pub,
      isLegitimate: true
    };
  });
  return repo;
}

function apDiscovery() {
  const allAPs = getAllAPs();
  return Object.values(allAPs).map(ap => ({
    bssid: ap.bssid,
    pos: ap.pos,
    ed25519Pub: ap.sign.pub,
    x25519Pub: ap.kex.pub,
    isLegitimate: ap.isLegitimate,
    isGuest: ap.isGuest || false,
    signalStrength: ap.signalStrength,
    detectorBelief: DETECTORS.get(ap.bssid)?.posteriorEvil || 0
  }));
}

function makeBeacon(ap) {
  const beacon = { apName: ap.bssid, ts: now(), load: ap.load };
  const sig = signEd25519(ap.sign.priv, Buffer.from(JSON.stringify(beacon)));
  return { ...beacon, sig };
}

setInterval(() => {
  const allAPs = getAllAPs();
  io.emit('beacons', Object.values(allAPs).map(makeBeacon));
}, 2000);

// ============= PACKET PROCESSING =============

const NONCE_TTL_MS = 120000;

function pruneReplay(ap) {
  const t = now();
  for (const n of Array.from(ap.replay)) {
    const parts = String(n).split(':');
    if (parts.length > 0) {
      const ts = Number(parts[0]);
      if (!isNaN(ts) && t - ts > NONCE_TTL_MS) ap.replay.delete(n);
    }
  }
}

function verifyAndDecryptAtAP(packet) {
  const allAPs = getAllAPs();
  const ap = allAPs[packet.header.toAp];
  if (!ap) return { ok: false, reason: 'dest AP not found' };
  
  const age = Math.abs(now() - packet.header.ts);
  if (age > tsTolSecs * 1000) {
    return { ok: false, reason: `stale ts ${Math.round(age/1000)}s` };
  }
  
  const trustedRepo = getTrustedRepo();
  const isKnownLegitimateAP = trustedRepo[packet.header.toAp] !== undefined;
  
  if (!isKnownLegitimateAP && !ap.isLegitimate) {
    return { ok: false, reason: 'untrusted AP - not in repository' };
  }
  
  const head = Buffer.from(JSON.stringify(packet.header));
  const sigPayload = Buffer.concat([head, Buffer.from(packet.body.ct, 'base64')]);
  const sigOK = verifyEd25519(packet.header.devEd25519Pub, sigPayload, packet.sig);
  
  if (!sigOK) return { ok: false, reason: 'bad signature' };
  
  pruneReplay(ap);
  if (ap.replay.has(packet.body.nonce)) {
    return { ok: false, reason: 'replay detected' };
  }
  ap.replay.add(packet.body.nonce);
  
  try {
    const shared = deriveSharedX25519(ap.kex.priv, packet.header.devX25519Pub);
    const key = hkdf(shared, Buffer.from('wifi-sim-salt'), Buffer.from('ap-payload'), 32);
    const pt = decryptGCM({iv: packet.body.iv, ct: packet.body.ct, tag: packet.body.tag}, key, head);
    return { ok: true, plaintext: pt };
  } catch(e) {
    return { ok: false, reason: 'decrypt failed: ' + e.message };
  }
}

// ============= DEVICE PACKET GENERATION =============

const deviceTimers = {};

function startDeviceBurst(id) {
  if (deviceTimers[id]) return;
  const rate = cfg.packetBurstRatePerDevice || 50;
  const ms = Math.max(20, Math.floor(1000 / rate));
  deviceTimers[id] = setInterval(() => createSendPacket(id), ms);
}

function stopDeviceBurst(id) {
  clearInterval(deviceTimers[id]);
  delete deviceTimers[id];
}

function createSendPacket(id) {
  const dev = DEVICES[id];
  if (!dev) return;
  
  const allAPs = getAllAPs();
  const apKeys = Object.keys(allAPs);
  if (apKeys.length === 0) return;
  
  // Select destination AP
  let dst;
  if (ACTIVE_STRATEGY === 'AVOID') {
    // AVOID: Filter out suspected evil APs
    const availableAPs = apKeys.filter(bssid => {
      const detector = DETECTORS.get(bssid);
      if (!detector) return true;
      
      if (detector.isLikelyEvil(0.3) && detector.getConfidence() > 0.4) {
        AVOIDED_APS.add(bssid);
        return false;
      }
      return true;
    });
    
    const targetPool = availableAPs.length > 0 ? availableAPs : Object.keys(LEGITIMATE_APS);
    dst = targetPool[Math.floor(Math.random() * targetPool.length)];
  } else {
    // TRUST and VERIFY: Use any AP
    dst = apKeys[Math.floor(Math.random() * apKeys.length)];
  }
  
  const srcAp = dev.connectedTo || 'AP1';
  const ts = now();
  
  const header = {
    from: id, toAp: dst, ts,
    devX25519Pub: dev.x.pub,
    devEd25519Pub: dev.ed.pub
  };
  
  const bodyObj = {
    msg: 'micro-pkt',
    nonce: `${ts}:${Math.random().toString(36).slice(2, 10)}`
  };
  
  const dstAP = allAPs[dst];
  const actuallyEvil = !dstAP?.isLegitimate;
  
  // Build packet
  let packet = null;
  let verdict = { ok: false, reason: 'unknown' };
  
  if (dstAP && dstAP.isLegitimate) {
    const sharedDev = deriveSharedX25519(dev.x.priv, dstAP.kex.pub);
    const keyDev = hkdf(sharedDev, Buffer.from('wifi-sim-salt'), Buffer.from('ap-payload'), 32);
    const headerBuf = Buffer.from(JSON.stringify(header));
    const enc = encryptGCM(JSON.stringify(bodyObj), keyDev, headerBuf);
    const sig = signEd25519(dev.ed.priv, Buffer.concat([headerBuf, Buffer.from(enc.ct, 'base64')]));
    
    packet = {
      header,
      body: { iv: enc.iv, ct: enc.ct, tag: enc.tag, nonce: bodyObj.nonce },
      sig
    };
    
    verdict = verifyAndDecryptAtAP(packet);
  }
  
  // Calculate cost based on ACTIVE_STRATEGY
  let cost = 0;
  let wasAvoided = false;
  
  if (ACTIVE_STRATEGY === 'TRUST') {
    // TRUST: Blind trust, high penalty if evil
    if (actuallyEvil) {
      cost = PAYOFF_MATRIX.TRUST_DEFECT.cost;
      verdict = { ok: false, reason: 'evil AP captured packet' };
    } else {
      cost = PAYOFF_MATRIX.TRUST_COOPERATE.cost;
    }
    
  } else if (ACTIVE_STRATEGY === 'VERIFY') {
    // VERIFY: Always verify, low penalty if evil caught
    if (actuallyEvil) {
      cost = PAYOFF_MATRIX.VERIFY_DEFECT.cost;
      verdict = { ok: false, reason: 'evil AP detected via verification' };
    } else {
      cost = PAYOFF_MATRIX.VERIFY_COOPERATE.cost;
    }
    
  } else { // AVOID
    // AVOID: Route around suspected evil APs
    if (AVOIDED_APS.has(dst)) {
      wasAvoided = true;
      cost = PAYOFF_MATRIX.AVOID_DEFECT.cost;
      verdict = { ok: false, reason: 'avoided suspicious AP' };
      STATS.packetsAvoided++;
    } else {
      if (actuallyEvil) {
        cost = PAYOFF_MATRIX.AVOID_DEFECT.cost;
        verdict = { ok: false, reason: 'evil AP not yet detected' };
      } else {
        cost = PAYOFF_MATRIX.AVOID_COOPERATE.cost;
      }
    }
  }
  
  // Update statistics
  STATS.totalSent++;
  PER_MODE[ACTIVE_STRATEGY].sent++;
  PER_MODE[ACTIVE_STRATEGY].cost += cost;
  costSinceLastTick += cost;
  STATS.cumulativeCost += cost;

  
  if (verdict.ok) {
    STATS.totalDelivered++;
    dev.stats.sent++;
    PER_MODE[ACTIVE_STRATEGY].delivered++;
  } else {
    STATS.dropped++;
    PER_MODE[ACTIVE_STRATEGY].dropped++;
  }
  
  // Update detector
  const detector = DETECTORS.get(dst);
  if (detector) {
    detector.observePacket(verdict.ok);
    
    if (detector.isLikelyEvil() && detector.getConfidence() > 0.5 && actuallyEvil) {
      const wasAlreadyCounted = detector.hasBeenCounted || false;
      if (!wasAlreadyCounted) {
        STATS.evilAPsDetectedCorrectly++;
        detector.hasBeenCounted = true;
        console.log(`✅ [DETECTION] ${dst} identified as evil (posterior: ${detector.posteriorEvil.toFixed(3)})`);
      }
    }
  }
  
  // Emit visualization event
  io.emit('packetCreated', {
    from: id, toAp: dst,
    fromPos: dev.pos, toPos: dstAP ? dstAP.pos : { x: 500, y: 300 },
    ok: verdict.ok,
    detectedAsEvil: detector?.isLikelyEvil() || false,
    wasAvoided: wasAvoided,
    strategy: ACTIVE_STRATEGY,
    cost: cost
  });
}

function updateDetectionAccuracy() {
  let correct = 0, total = 0;
  
  const allAPs = getAllAPs();
  
  for (const [bssid, detector] of DETECTORS.entries()) {
    const ap = allAPs[bssid];
    if (!ap) continue;
    
    const actuallyEvil = !ap.isLegitimate;
    const detectedEvil = detector.isLikelyEvil(0.2);
    
    total++;
    if (detectedEvil === actuallyEvil) correct++;
  }
  
  return total > 0 ? (correct / total) : 1;
}

setInterval(() => {
  const allAPs = getAllAPs();
  Object.values(allAPs).forEach(ap => {
    ap.load = Math.max(0, ap.load - 2);
  });
}, 1000);

// ============= SOCKET EVENTS =============

io.on('connection', socket => {
  socket.on('getAPs', cb => cb(apDiscovery()));
  socket.on('getTrustedRepo', cb => cb(getTrustedRepo()));
  
  socket.on('setTolerance', secs => {
    const s = Number(secs) || tsTolSecs;
    tsTolSecs = Math.max(5, Math.min(300, s));
    console.log(`Timestamp tolerance set to ${tsTolSecs}s`);
  });

  socket.on('setSensitivity', (sensitivity) => {
    DATA_SENSITIVITY = sensitivity === 'sensitive' ? 'sensitive' : 'non';
    PAYOFF_MATRIX = PAYOFF_MATRICES[DATA_SENSITIVITY];
    console.log(`📊 Data sensitivity set to: ${DATA_SENSITIVITY}`);
    io.emit('sensitivityUpdated', { 
      sensitivity: DATA_SENSITIVITY,
      payoffMatrix: PAYOFF_MATRIX 
    });
  });

  socket.on('setEvilProbability', (percent) => {
    const p = Math.max(0, Math.min(100, Number(percent)||0)) / 100;
    if (!Number.isFinite(p)) return;
    SPOOF_CONFIG.evilProbability = p;
    console.log(`🎚️ Evil guest AP probability set to ${(p*100).toFixed(0)}%`);
    io.emit('evilProbabilityUpdated', { evilProbability: p });
  });

  socket.on('connectDevice', ({ id }) => {
    if (!id) return;
    const ed = genEd25519();
    const xk = genX25519();
    
    DEVICES[id] = DEVICES[id] || {
      id,
      ed: { pub: ed.publicKey, priv: ed.privateKey },
      x:  { pub: xk.publicKey, priv: xk.privateKey },
      connectedTo: 'AP1',
      pos: { x: 80 + Object.keys(DEVICES).length * 40, y: 500 },
      stats: { sent: 0, delivered: 0 }
    };
    
    socket.emit('deviceConnected', DEVICES[id]);
    io.emit('devices', Object.values(DEVICES));
    startDeviceBurst(id);
  });

  socket.on('manualToggleEvil', (bssid) => {
    const allAPs = getAllAPs();
    const ap = allAPs[bssid];
    
    if (!ap) {
      console.log(`AP ${bssid} not found`);
      return;
    }
    
    ap.isLegitimate = !ap.isLegitimate;
    
    console.log(`🔄 [MANUAL TOGGLE] ${bssid} is now ${ap.isLegitimate ? 'LEGITIMATE' : 'EVIL'}`);
    
    if (ap.isLegitimate) {
      if (EVIL_APS[bssid]) delete EVIL_APS[bssid];
      AVOIDED_APS.delete(bssid);
    } else {
      EVIL_APS[bssid] = ap;
      STATS.spoofersSpawned++;
    }
    
    io.emit('apStateChanged', {
      bssid: bssid,
      isLegitimate: ap.isLegitimate
    });
    
    io.emit('beacons', Object.values(allAPs).map(makeBeacon));
  });

  socket.on('manualSpawnEvil', () => {
    spawnGuestAPs();
  });

  socket.on('statsRequest', cb => {
    const detectorStates = {};
    for (const [bssid, detector] of DETECTORS.entries()) {
      const bufferProgress = detector.getBufferProgress();
      detectorStates[bssid] = {
        posteriorEvil: detector.posteriorEvil,
        confidence: detector.getConfidence(),
        isLikelyEvil: detector.isLikelyEvil(),
        observationCount: detector.observations.length,
        bufferProgress: bufferProgress
      };
    }
    
    cb({
      ...STATS,
      evilProbability: SPOOF_CONFIG.evilProbability,
      detectors: detectorStates,
      activeEvilAPs: Object.keys(EVIL_APS).length,
      avoidedAPsCount: AVOIDED_APS.size,
      dataSensitivity: DATA_SENSITIVITY
    });
  });
});

setInterval(() => {
  const detectorStates = {};
  for (const [bssid, detector] of DETECTORS.entries()) {
    const bufferProgress = detector.getBufferProgress();
    detectorStates[bssid] = {
      posteriorEvil: detector.posteriorEvil,
      confidence: detector.getConfidence(),
      isLikelyEvil: detector.isLikelyEvil(),
      bufferProgress: bufferProgress
    };
  }
  
  const allAPs = getAllAPs();
  const apLoads = {};
  for (const [bssid, ap] of Object.entries(allAPs)) {
    apLoads[bssid] = (ap.load / ap.capacity) * 100;
  }
  
io.emit('stats', { 
  dataSensitivity: DATA_SENSITIVITY, 
  ...STATS,
  actualCost: costSinceLastTick,
  cumulativeCost: STATS.cumulativeCost,
  detectionAccuracy: updateDetectionAccuracy(),
  detectors: detectorStates,
  activeEvilAPs: Object.keys(EVIL_APS).length,
  activeGuestAPs: Object.keys(GUEST_APS).length,
  avoidedAPsCount: AVOIDED_APS.size,
  payoffMatrix: PAYOFF_MATRIX,
  apLoads,
  activeStrategy: ACTIVE_STRATEGY,
  modeEndsAt: MODE_ENDS_AT,
  perMode: PER_MODE,
  evilProbability: SPOOF_CONFIG.evilProbability
});

// Reset counter *after* emitting
costSinceLastTick = 0;
}, 1000);

app.get('/ap-discovery', (req, res) => res.json(apDiscovery()));

server.listen(PORT, () => {
  console.log(`✓ Server running at http://localhost:${PORT}/main.html`);
  console.log(`✓ Game Theory Engine: Nash Equilibrium + Bayesian Inference`);
  console.log(`✓ Strategy rotation: TRUST → VERIFY → AVOID (30s windows)`);
  console.log(`✓ Continuous Guest AP spawning: 4 APs every 15s (40% evil by default)`);
  console.log(`✓ Attack detection using probabilistic inference`);
  console.log(`✓ Data Sensitivity: ${DATA_SENSITIVITY}`);
});