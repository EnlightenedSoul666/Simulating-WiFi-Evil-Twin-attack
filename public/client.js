// public/client.js - COMPLETE VERSION
const io_ = io();
const cv = document.getElementById('cv');
const ctx = cv.getContext('2d');

function sizeCanvas(){
  const rect = cv.getBoundingClientRect();
  cv.width  = Math.max(600, Math.floor(rect.width));
  cv.height = Math.max(400, Math.floor(rect.height));
}
sizeCanvas();
window.addEventListener('resize', sizeCanvas);

const el = id => document.getElementById(id);
const deviceId  = el('deviceId');
const connectBtn= el('connect');
const toggleSensitivity = el('toggleSensitivity');
if (toggleSensitivity) {
  let currentMode = 'non';
  toggleSensitivity.onclick = () => {
    const next = (currentMode === 'sensitive') ? 'non' : 'sensitive';
    io_.emit('setSensitivity', next);
  };
  io_.on('sensitivityMode', ({ mode }) => {
    currentMode = mode;
    toggleSensitivity.textContent = `Data: ${mode === 'sensitive' ? 'Sensitive 🔒' : 'Non-sensitive 🗂️'}`;
    if (typeof showAlert === 'function') showAlert(`Data sensitivity set to ${mode}`, mode === 'sensitive' ? 'warning' : 'info');
  });
}

const openGraph = el('openGraph');
const speed     = el('speed');
const toggleEvil= el('toggleEvil');
const statsEl   = el('stats');
const evilPct   = el('evilPct');
const evilPctVal= el('evilPctVal');

let APs = [];
let DEVICES = {};
let me = null;
const parts = [];
let infoMsg = "Click Connect to start packets";

// Track AP states for visual transitions
const apStates = new Map(); // bssid -> { currentColor, detectionBelief }

openGraph.onclick = () => window.open('/graph.html', '_blank');

toggleEvil.onclick = () => {
  io_.emit('manualToggleEvil', 'AP1');
};

// Evil AP probability slider
if (evilPct) {
  evilPct.oninput = () => {
    evilPctVal.textContent = evilPct.value + '%';
  };
  evilPct.onchange = () => {
    io_.emit('setEvilProbability', Number(evilPct.value));
    showAlert(`🎚️ Evil AP probability set to ${evilPct.value}%`, 'info');
  };
}

function discoverAPs(){ 
  io_.emit('getAPs', (list) => { 
    APs = list || [];
    // Initialize states for new APs
    APs.forEach(ap => {
      if (!apStates.has(ap.bssid)) {
        const initialBelief = ap.detectorBelief || 0.1;
        apStates.set(ap.bssid, {
          currentColor: getColorFromBelief(initialBelief),
          detectionBelief: initialBelief,
          isActuallyEvil: !ap.isLegitimate,
          isGuest: ap.isGuest || false,
          spawnTime: Date.now()
        });
      }
    });
  });
}

// Color mapping based on P(evil)
// 0.0 - 0.2: Blue (legitimate)
// 0.2 - 0.5: Orange (suspicious)  
// 0.5 - 1.0: Red (evil detected)
function getColorFromBelief(belief) {
  if (belief < 0.2) {
    // Blue zone: Legitimate
    const intensity = 1 - (belief / 0.2);
    return {
      r: 33 + (222 * (1 - intensity)),
      g: 150 + (105 * (1 - intensity)),
      b: 243 + (12 * (1 - intensity))
    };
  } else if (belief < 0.5) {
    // Orange zone: Suspicious
    const t = (belief - 0.2) / 0.3;
    return {
      r: 255,
      g: 152 - (70 * t),
      b: 0
    };
  } else {
    // Red zone: Evil detected
    const intensity = (belief - 0.5) / 0.5;
    return {
      r: 255,
      g: 82 * (1 - intensity),
      b: 82 * (1 - intensity)
    };
  }
}

io_.on('connect', discoverAPs);
window.addEventListener('load', discoverAPs);

io_.on('guestAPSpawned', ({ bssid, pos, mimicking, isEvil }) => {
  console.log(`${isEvil ? '🚨' : '✅'} Guest AP spawned: ${bssid} mimicking ${mimicking} (${isEvil ? 'EVIL' : 'GOOD'})`);
  
  apStates.set(bssid, {
    currentColor: getColorFromBelief(0.1),
    detectionBelief: 0.1,
    isActuallyEvil: isEvil,
    isGuest: true,
    spawnTime: Date.now()
  });
  
  discoverAPs();
  showAlert(`${isEvil ? '🚨' : '✅'} Guest AP: ${bssid.slice(0, 20)}...`, isEvil ? 'warning' : 'info');
});

io_.on('guestAPDespawned', ({ bssid }) => {
  console.log(`♻️ Guest AP despawned: ${bssid}`);
  apStates.delete(bssid);
  discoverAPs();
});

io_.on('apStateChanged', ({ bssid, isLegitimate }) => {
  const ap = APs.find(a => a.bssid === bssid);
  if (ap) {
    ap.isLegitimate = isLegitimate;
    const state = apStates.get(bssid);
    if (state) {
      state.isActuallyEvil = !isLegitimate;
    }
  }
  showAlert(`🔄 ${bssid} toggled to ${isLegitimate ? 'LEGITIMATE' : 'EVIL'}`, 
    isLegitimate ? 'success' : 'danger');
});

connectBtn.onclick = () => {
  const id = deviceId.value || `Device${Math.floor(Math.random()*1000)}`;
  io_.emit('getTrustedRepo', (_repo)=> io_.emit('connectDevice', { id }) );
};

io_.on('deviceConnected', (dev) => {
  DEVICES[dev.id] = { pos: dev.pos }; 
  me = dev.id; 
  infoMsg = "";
  showAlert(`✅ Device ${dev.id} connected`, 'success');
});

let beaconAges = {};
io_.on('beacons', (arr)=>{
  const t=Date.now(); 
  beaconAges={}; 
  (arr||[]).forEach(b=>beaconAges[b.apName]=Math.round((t-b.ts)/1000));
});

io_.on('stats', s => {
  statsEl.innerHTML = `Sent: ${s.totalSent} | Delivered: ${s.totalDelivered} | Dropped: ${s.dropped} | Evil APs: ${s.activeEvilAPs || 0} | Guest APs: ${s.activeGuestAPs || 0} | Avoided: ${s.avoidedAPsCount || 0}`;
  if (typeof s.evilProbability === 'number' && evilPct && evilPctVal) {
    const pct = Math.round(s.evilProbability * 100);
    evilPct.value = String(Math.min(50, Math.max(0, pct)));
    evilPctVal.textContent = pct + '%';
  }
  
  // Update colors based on Bayesian belief updates
  if (s.detectors) {
    Object.entries(s.detectors).forEach(([bssid, detector]) => {
      const state = apStates.get(bssid);
      if (state) {
        state.detectionBelief = (state.detectionBelief ?? detector.posteriorEvil);
        // slow, gradual belief update (EMA)
        state.detectionBelief = state.detectionBelief * 0.95 + detector.posteriorEvil * 0.05;
        state.targetColor = getColorFromBelief(detector.posteriorEvil);
      }
    });
  }
});

io_.on('packetCreated', ({ from, toAp, fromPos, toPos, ok, detectedAsEvil, wasAvoided }) => {
  const spd = parseInt(speed.value||'12',10);
  
  // Color based on status
  let color;
  if (wasAvoided) {
    color = 'rgba(255,193,7,0.9)'; // Yellow for avoided
  } else if (ok) {
    color = 'rgba(129,199,132,0.9)'; // Green for success
  } else {
    color = detectedAsEvil ? 'rgba(255,82,82,0.9)' : 'rgba(255,152,0,0.8)';
  }
  
  parts.push({ 
    x: fromPos.x, 
    y: fromPos.y, 
    tx: toPos.x + (Math.random()*36-18), 
    ty: toPos.y + (Math.random()*36-18), 
    spd: spd/10, 
    life: 0,
    color: color,
    ok: ok,
    avoided: wasAvoided
  });
});

function showAlert(msg, type) {
  const alertDiv = document.createElement('div');
  const colors = {
    danger: 'rgba(255,82,82,0.95)',
    success: 'rgba(129,199,132,0.95)',
    info: 'rgba(100,181,246,0.95)',
    warning: 'rgba(255,193,7,0.95)'
  };
  
  alertDiv.style.cssText = `
    position: fixed;
    top: ${80 + (document.querySelectorAll('.alert-toast').length * 60)}px;
    right: 20px;
    padding: 12px 16px;
    background: ${colors[type] || colors.info};
    color: white;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    z-index: 1000;
    animation: slideIn 0.3s ease-out;
  `;
  alertDiv.className = 'alert-toast';
  alertDiv.textContent = msg;
  document.body.appendChild(alertDiv);
  
  setTimeout(() => {
    alertDiv.style.animation = 'slideOut 0.3s ease-in';
    setTimeout(() => alertDiv.remove(), 300);
  }, 3000);
}

// Smooth color interpolation
function lerpColor(current, target, speed = 0.015) {
  return {
    r: current.r + (target.r - current.r) * speed,
    g: current.g + (target.g - current.g) * speed,
    b: current.b + (target.b - current.b) * speed
  };
}

function draw(){
  ctx.clearRect(0, 0, cv.width, cv.height);
  
  // Draw APs with Bayesian color transitions
  APs.forEach(ap => {
    const state = apStates.get(ap.bssid);
    if (state) {
      // Smooth transition based on target color
      if (state.targetColor) {
        state.currentColor = lerpColor(state.currentColor, state.targetColor, 0.01);
      }
      
      const { r, g, b } = state.currentColor;
      const belief = state.detectionBelief;
      
      // Main AP circle
      ctx.beginPath();
      ctx.arc(ap.pos.x, ap.pos.y, 20, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, 0.92)`;
      ctx.fill();
      
      // Guest AP indicator
      if (state.isGuest) {
        ctx.strokeStyle = 'rgba(255,193,7,0.6)';
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.arc(ap.pos.x, ap.pos.y, 24, 0, Math.PI * 2);
        ctx.stroke();
        ctx.setLineDash([]);
        // Label rogue vs evil twin
        ctx.fillStyle = state.isActuallyEvil ? '#ff5252' : '#ffc107';
        ctx.font = '10px Inter';
        ctx.textAlign = 'center';
        ctx.fillText(state.isActuallyEvil ? 'EVIL TWIN' : 'ROGUE', ap.pos.x, ap.pos.y + 52);
      }
      
      // Detection indicator ring
      if (belief > 0.2) {
        const ringSize = 24 + (belief * 8);
        ctx.beginPath();
        ctx.arc(ap.pos.x, ap.pos.y, ringSize, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 152, 0, ${belief * 0.8})`;
        ctx.lineWidth = 2 + (belief * 2);
        ctx.stroke();
      }
      
      // Warning pulse for high detection (>50%)
      if (belief > 0.5) {
        const pulse = Math.sin(Date.now() / 150) * 0.3 + 0.7;
        ctx.beginPath();
        ctx.arc(ap.pos.x, ap.pos.y, 30, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 82, 82, ${pulse * 0.7})`;
        ctx.lineWidth = 3;
        ctx.stroke();
        
        // Warning icon
        ctx.fillStyle = `rgba(255, 255, 255, ${pulse})`;
        ctx.font = 'bold 16px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('⚠', ap.pos.x, ap.pos.y - 32);
      }
      
      // Success checkmark for confirmed legitimate (<20%)
      if (belief < 0.2 && !state.isActuallyEvil) {
        ctx.fillStyle = 'rgba(129,199,132,0.8)';
        ctx.font = 'bold 14px Arial';
        ctx.textAlign = 'center';
        ctx.fillText('✓', ap.pos.x + 14, ap.pos.y - 14);
      }
    } else {
      // Fallback rendering with prior belief color (avoid premature red)
      const prior = getColorFromBelief(0.1);
      ctx.beginPath();
      ctx.arc(ap.pos.x, ap.pos.y, 20, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${Math.round(prior.r)},${Math.round(prior.g)},${Math.round(prior.b)},0.92)`;
      ctx.fill();
    }
    
    // Labels
    ctx.fillStyle = '#fff';
    ctx.font = 'bold 11px Inter';
    ctx.textAlign = 'center';
    ctx.fillText(ap.bssid.slice(0, 15), ap.pos.x, ap.pos.y + 38);
    
    const age = beaconAges[ap.bssid] ?? '-';
    const apState = apStates.get(ap.bssid);
    const detectionText = apState ? `${(apState.detectionBelief * 100).toFixed(0)}%` : '-';
    
    // Color code the detection percentage
    let detectionColor = '#9db0c7';
    if (apState) {
      if (apState.detectionBelief > 0.5) detectionColor = '#ff5252';
      else if (apState.detectionBelief > 0.2) detectionColor = '#ff9800';
      else detectionColor = '#81c784';
    }
    
    ctx.fillStyle = detectionColor;
    ctx.font = '11px Inter';
    ctx.fillText(`P(evil)=${detectionText}`, ap.pos.x, ap.pos.y - 28);
    
    // Show buffer progress
    if (apState && apState.bufferProgress) {
      const progress = apState.bufferProgress;
      if (progress.current > 0 && progress.current < progress.target) {
        ctx.fillStyle = '#7a8a9f';
        ctx.font = '9px Inter';
        ctx.fillText(`Learning: ${progress.current}/${progress.target}`, ap.pos.x, ap.pos.y - 16);
      }
    }
    
    ctx.fillStyle = '#7a8a9f';
    ctx.font = '10px Inter';
    ctx.fillText(`age ${age}s`, ap.pos.x, ap.pos.y - 40);
  });
  
  // Device
  if (me) {
    const d = DEVICES[me] || { pos: { x: 80, y: 500 } };
    ctx.fillStyle = '#bfe8ff';
    ctx.fillRect(d.pos.x - 6, d.pos.y - 6, 14, 14);
    ctx.strokeStyle = '#64b5f6';
    ctx.lineWidth = 2;
    ctx.strokeRect(d.pos.x - 6, d.pos.y - 6, 14, 14);
    
    ctx.fillStyle = '#64b5f6';
    ctx.font = '12px Inter';
    ctx.textAlign = 'left';
    ctx.fillText(me, d.pos.x - 4, d.pos.y + 22);
  }
  
  // Particles with trails
  for (let i = parts.length - 1; i >= 0; --i) {
    const p = parts[i];
    const dx = p.tx - p.x;
    const dy = p.ty - p.y;
    const dist = Math.hypot(dx, dy);
    const step = Math.min(dist, p.spd);
    
    if (dist <= 0.5) {
      // Arrival burst
      ctx.beginPath();
      ctx.arc(p.x, p.y, 8, 0, Math.PI * 2);
      if (p.avoided) {
        ctx.fillStyle = 'rgba(255,193,7,0.3)';
      } else {
        ctx.fillStyle = p.ok ? 'rgba(129,199,132,0.3)' : 'rgba(255,82,82,0.3)';
      }
      ctx.fill();
      parts.splice(i, 1);
      continue;
    }
    
    p.x += dx / dist * step;
    p.y += dy / dist * step;
    p.life++;
    
    // Main particle
    ctx.beginPath();
    const r = 2 + Math.sin(p.life / 5) * 0.5;
    ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.fill();
    
    // Trail effect
    if (p.life % 2 === 0) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, r * 2.5, 0, Math.PI * 2);
      if (p.avoided) {
        ctx.fillStyle = 'rgba(255,193,7,0.1)';
      } else {
        ctx.fillStyle = p.ok ? 'rgba(129,199,132,0.1)' : 'rgba(255,82,82,0.1)';
      }
      ctx.fill();
    }
  }
  
  // Info overlay
  if (!APs.length) {
    ctx.fillStyle = 'rgba(100,181,246,0.9)';
    ctx.font = '14px Inter';
    ctx.textAlign = 'left';
    ctx.fillText('🔍 Discovering APs… (server must be running)', 28, 40);
  } else if (infoMsg) {
    ctx.fillStyle = 'rgba(100,181,246,0.9)';
    ctx.font = '14px Inter';
    ctx.textAlign = 'left';
    ctx.fillText(infoMsg, 28, 40);
  }
  
  // Legend
  ctx.textAlign = 'left';
  ctx.font = '11px Inter';
  
  ctx.fillStyle = 'rgba(33,150,243,0.9)';
  ctx.fillRect(28, cv.height - 100, 12, 12);
  ctx.fillStyle = '#9db0c7';
  ctx.fillText('Legitimate (P<20%)', 45, cv.height - 90);
  
  ctx.fillStyle = 'rgba(255,152,0,0.9)';
  ctx.fillRect(28, cv.height - 80, 12, 12);
  ctx.fillStyle = '#9db0c7';
  ctx.fillText('Suspicious (P=20-50%)', 45, cv.height - 70);
  
  ctx.fillStyle = 'rgba(255,82,82,0.9)';
  ctx.fillRect(28, cv.height - 60, 12, 12);
  ctx.fillStyle = '#9db0c7';
  ctx.fillText('Evil Detected (P>50%)', 45, cv.height - 50);
  
  ctx.fillStyle = 'rgba(255,193,7,0.9)';
  ctx.fillRect(28, cv.height - 40, 12, 12);
  ctx.fillStyle = '#9db0c7';
  ctx.fillText('Avoided AP (No Traffic)', 45, cv.height - 30);
  
  requestAnimationFrame(draw);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(400px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(400px); opacity: 0; }
  }
`;
document.head.appendChild(style);

draw();

io_.on('evilProbabilityUpdated', ({ evilProbability }) => {
  if (evilPct && evilPctVal && typeof evilProbability === 'number') {
    const pct = Math.round(evilProbability * 100);
    evilPct.value = String(Math.min(50, Math.max(0, pct)));
    evilPctVal.textContent = pct + '%';
  }
});
