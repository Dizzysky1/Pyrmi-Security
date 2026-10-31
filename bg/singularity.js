/* The pyrmi.com background: a particle singularity (accretion disk, matter spiralling in, polar jets) behind the page.
   Every particle's path is worked out in the vertex shader from time alone, so there's no simulation pass and the
   cost stays low. It pauses when the tab is hidden, drops quality on slow devices, draws one still frame for
   reduced motion, and leaves the CSS fallback in place when WebGL isn't there. */
import * as THREE from '../vendor/three-r170/three.module.min.js';
import { EffectComposer } from '../vendor/three-r170/addons/postprocessing/EffectComposer.js';
import { RenderPass } from '../vendor/three-r170/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from '../vendor/three-r170/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from '../vendor/three-r170/addons/postprocessing/OutputPass.js';
import { ShaderPass } from '../vendor/three-r170/addons/postprocessing/ShaderPass.js';

const canvas = document.getElementById('gl');
const root = document.documentElement;
// Add ?bg=debug to a page's address to see what the background is doing (for checking a device or a browser).
const DEBUG = /[?&]bg=debug\b/.test(location.search);
function note(msg) {
  if (!DEBUG) return;
  let el = document.getElementById('bg-debug');
  if (!el) { el = document.createElement('div'); el.id = 'bg-debug'; el.style.cssText = 'position:fixed;left:8px;bottom:8px;z-index:9;font:12px monospace;color:#fff;background:#000a;padding:4px 8px;border-radius:6px'; document.body.appendChild(el); }
  el.textContent = 'bg: ' + msg;
}

function start() {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const mobile = matchMedia('(pointer: coarse)').matches || Math.min(innerWidth, innerHeight) < 700;
  const quiet = canvas.dataset.mode === 'quiet'; // docs and dashboard: dimmer and lighter
  const N = Math.round((mobile ? 16000 : 52000) * (quiet ? 0.6 : 1));
  let PR = Math.min(devicePixelRatio || 1, mobile ? 1.25 : 1.75);

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: mobile ? 'low-power' : 'high-performance' });
  } catch (e) { note('no WebGL (' + e.message + ')'); return; } // no WebGL: the CSS backdrop stays
  renderer.debug.onShaderError = (gl, program, vs, fs) => note('shader error: ' + (gl.getShaderInfoLog(vs) || gl.getShaderInfoLog(fs) || gl.getProgramInfoLog(program) || '?').slice(0, 200));
  renderer.setPixelRatio(PR);
  renderer.setSize(innerWidth, innerHeight, false);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.setClearColor(0x030308, 1);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(50, innerWidth / innerHeight, 0.1, 2000);

  // ---- particles ------------------------------------------------------------------------------------------------
  const A = new Float32Array(N * 3), B = new Float32Array(N * 3), G = new Float32Array(N * 2);
  for (let i = 0; i < N; i++) {
    A[i * 3] = Math.random(); A[i * 3 + 1] = Math.random(); A[i * 3 + 2] = Math.random();
    B[i * 3] = Math.random(); B[i * 3 + 1] = Math.random(); B[i * 3 + 2] = Math.random();
    const m = Math.sqrt(-2 * Math.log(Math.max(Math.random(), 1e-6))), th = Math.random() * Math.PI * 2;
    G[i * 2] = m * Math.cos(th); G[i * 2 + 1] = m * Math.sin(th);
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(N * 3), 3)); // unused, three needs it
  geo.setAttribute('aA', new THREE.BufferAttribute(A, 3));
  geo.setAttribute('aB', new THREE.BufferAttribute(B, 3));
  geo.setAttribute('aG', new THREE.BufferAttribute(G, 2));

  const pMat = new THREE.ShaderMaterial({
    uniforms: {
      uTime: { value: 0 }, uSize: { value: mobile ? 64 : 50 }, uPR: { value: PR }, uIntensity: { value: mobile ? 0.55 : 0.32 },
      uColA: { value: new THREE.Color('#ff2e55') }, uColB: { value: new THREE.Color('#8a5cff') }, uHot: { value: new THREE.Color('#fff1f4') },
    },
    vertexShader: /* glsl */`
      attribute vec3 aA, aB; attribute vec2 aG;
      uniform float uTime, uSize, uPR, uIntensity;
      uniform vec3 uColA, uColB, uHot;
      varying vec3 vColor;
      #define TAU 6.28318530718
      void main(){
        vec3 p; float heat; float fade=1.0; float t=uTime;
        if(aA.x<0.78){
          // accretion disk with Keplerian shear: inner orbits outrun outer ones
          float r=3.0+pow(aA.y,1.6)*16.5;
          float ang=aA.z*TAU + t*9.0/pow(r,1.5);
          float wob=aG.y*0.05*r*0.3;
          p=vec3(cos(ang)*(r+wob), aG.x*(0.03+0.02*r), sin(ang)*(r+wob));
          heat=smoothstep(9.0,3.0,r);
        } else if(aA.x<0.92){
          // matter spiralling in and vanishing at the horizon
          float life=fract(aA.y + t*0.03*(0.6+aB.x));
          float r=mix(26.0,2.4,pow(life,0.7));
          float ang=aA.z*TAU + (26.0-r)*0.32 + t*0.25;
          p=vec3(cos(ang)*r, aG.x*0.04*r, sin(ang)*r);
          heat=smoothstep(8.0,2.4,r);
          fade=smoothstep(2.4,3.6,r)*smoothstep(26.0,22.0,r);
        } else {
          // twin polar jets streaming outward
          float side=aB.x<0.5?-1.0:1.0;
          float k=fract(aB.y + t*0.05);
          float len=pow(k,0.75)*24.0;
          float rad=(0.15+len*0.05)*sqrt(aB.z);
          float ang=aA.y*TAU + len*0.35 - t*1.4*side;
          p=vec3(cos(ang)*rad, side*(2.2+len), sin(ang)*rad);
          heat=1.0-k;
          fade=smoothstep(1.0,0.7,k);
        }
        vec4 mv=modelViewMatrix*vec4(p,1.0);
        gl_Position=projectionMatrix*mv;
        gl_PointSize=uSize*uPR*(0.35+aB.z*aB.z*1.4)*fade/max(-mv.z,0.1);
        vec3 col=mix(uColA,uColB,smoothstep(0.15,0.85,aB.y));
        col=mix(col,uHot,heat*0.8);
        vColor=col*(0.75+aA.y*0.5)*uIntensity*(1.0+heat*1.3)*fade;
      }`,
    fragmentShader: /* glsl */`
      varying vec3 vColor;
      void main(){
        vec2 c=gl_PointCoord-0.5; float d=dot(c,c);
        if(d>0.25) discard;
        gl_FragColor=vec4(vColor*exp(-d*14.0),1.0);
      }`,
    blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
  });
  const particles = new THREE.Points(geo, pMat);
  particles.frustumCulled = false;
  scene.add(particles);

  // ---- the horizon: a black sphere with a glowing rim, and a photon ring facing the camera ----------------------
  const rim = new THREE.Color('#ff4d6d');
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(2.25, mobile ? 12 : 24), new THREE.ShaderMaterial({
    uniforms: { uRim: { value: rim } },
    vertexShader: `varying vec3 vN, vV; void main(){ vec4 wp=modelMatrix*vec4(position,1.0); vN=normalize(mat3(modelMatrix)*normal); vV=normalize(cameraPosition-wp.xyz); gl_Position=projectionMatrix*viewMatrix*wp; }`,
    fragmentShader: `uniform vec3 uRim; varying vec3 vN, vV; void main(){ float f=pow(1.0-max(dot(normalize(vN),normalize(vV)),0.0),3.0); gl_FragColor=vec4(uRim*f*2.2,1.0); }`,
  }));
  scene.add(core);
  const ringMat = new THREE.ShaderMaterial({
    uniforms: { uRim: { value: rim }, uTime: { value: 0 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv*2.0-1.0; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
    fragmentShader: `uniform vec3 uRim; uniform float uTime; varying vec2 vUv;
      void main(){ float r=length(vUv), a=atan(vUv.y,vUv.x); float fl=0.85+0.15*sin(a*3.0+uTime*2.0);
        float ring=exp(-pow((r-0.55)/0.018,2.0))*2.0*fl + exp(-pow((r-0.55)/0.11,2.0))*0.3 + exp(-pow((r-0.55)/0.3,2.0))*0.07;
        gl_FragColor=vec4(uRim*ring,1.0); }`,
    blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
  });
  const ring = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), ringMat);
  ring.scale.setScalar(2.25 * 2.3);
  scene.add(ring);

  // ---- stars ----------------------------------------------------------------------------------------------------
  const SN = mobile ? 1200 : 3000;
  const sp = new Float32Array(SN * 3), ss = new Float32Array(SN), sph = new Float32Array(SN);
  for (let i = 0; i < SN; i++) {
    const u = Math.random() * 2 - 1, th = Math.random() * Math.PI * 2, s = Math.sqrt(1 - u * u), r = 400 + Math.random() * 300;
    sp.set([s * Math.cos(th) * r, u * r, s * Math.sin(th) * r], i * 3);
    ss[i] = Math.pow(Math.random(), 6) * 4 + 0.7; sph[i] = Math.random() * 100;
  }
  const sg = new THREE.BufferGeometry();
  sg.setAttribute('position', new THREE.BufferAttribute(sp, 3));
  sg.setAttribute('aSize', new THREE.BufferAttribute(ss, 1));
  sg.setAttribute('aPhase', new THREE.BufferAttribute(sph, 1));
  const starMat = new THREE.ShaderMaterial({
    uniforms: { uTime: { value: 0 }, uPR: { value: PR } },
    vertexShader: `attribute float aSize, aPhase; uniform float uTime, uPR; varying float vB;
      void main(){ vec4 mv=modelViewMatrix*vec4(position,1.0); gl_Position=projectionMatrix*mv;
        gl_PointSize=aSize*uPR; vB=(0.65+0.35*sin(uTime*(1.2+fract(aPhase)*2.5)+aPhase))*(0.25+aSize*0.18); }`,
    fragmentShader: `varying float vB; void main(){ vec2 c=gl_PointCoord-0.5; float d=dot(c,c); if(d>0.25) discard; gl_FragColor=vec4(vec3(0.8,0.85,1.0)*vB*exp(-d*18.0),1.0); }`,
    blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
  });
  scene.add(new THREE.Points(sg, starMat));

  // ---- post: bloom, then a vignette with a touch of grain ------------------------------------------------------
  const composer = new EffectComposer(renderer);
  composer.setPixelRatio(PR);
  composer.setSize(innerWidth, innerHeight);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(innerWidth, innerHeight), mobile ? 0.9 : 1.05, 0.6, 0.12);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());
  const finish = new ShaderPass({
    uniforms: { tDiffuse: { value: null }, uTime: { value: 0 }, uDim: { value: 1 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
    fragmentShader: `uniform sampler2D tDiffuse; uniform float uTime, uDim; varying vec2 vUv;
      float h(vec2 p){ vec3 p3=fract(vec3(p.xyx)*.1031); p3+=dot(p3,p3.yzx+33.33); return fract((p3.x+p3.y)*p3.z); }
      void main(){ vec3 col=texture2D(tDiffuse,vUv).rgb; float d=length(vUv-0.5);
        col*=mix(0.45,1.0,smoothstep(0.85,0.2,d))*uDim;
        col+=(h(gl_FragCoord.xy+fract(uTime*7.31)*917.0)-0.5)*0.02;
        gl_FragColor=vec4(col,1.0); }`,
  });
  composer.addPass(finish);

  // ---- layout: on wide screens the singularity sits to the right of the hero text ------------------------------
  function layout() {
    const w = innerWidth, h = innerHeight;
    camera.aspect = w / h;
    const shift = w >= 900 && !quiet ? -0.2 * w : 0;
    camera.setViewOffset(w, h, shift, 0, w, h);
    camera.updateProjectionMatrix();
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.resolution.set(w, h);
  }
  layout();
  addEventListener('resize', layout);

  // ---- motion: slow orbit, a little pointer parallax, and a tilt as you scroll --------------------------------
  const ptr = { x: 0, y: 0, tx: 0, ty: 0 };
  if (!reduce) addEventListener('pointermove', (e) => { ptr.tx = e.clientX / innerWidth - 0.5; ptr.ty = e.clientY / innerHeight - 0.5; }, { passive: true });
  let scrollK = 0;
  const readScroll = () => { scrollK = Math.min(1, scrollY / Math.max(innerHeight, 1)); };
  addEventListener('scroll', readScroll, { passive: true }); readScroll();

  let t = reduce ? 14 : 0, last = performance.now(), raf = 0, frames = 0, slow = 0, level = 0;
  function frame(now) {
    const dt = Math.min((now - last) / 1000, 1 / 20); last = now;
    if (!reduce) t += dt;
    ptr.x += (ptr.tx - ptr.x) * 0.04; ptr.y += (ptr.ty - ptr.y) * 0.04;
    const orbit = t * 0.035 + ptr.x * 0.5;
    const dist = (quiet ? 40 : 34) + scrollK * 6;
    const height = 8 + scrollK * 9 - ptr.y * 5;
    camera.position.set(Math.sin(orbit) * dist, height, Math.cos(orbit) * dist);
    camera.lookAt(0, 0, 0);
    ring.quaternion.copy(camera.quaternion);
    pMat.uniforms.uTime.value = t; ringMat.uniforms.uTime.value = t; starMat.uniforms.uTime.value = t; finish.uniforms.uTime.value = t;
    finish.uniforms.uDim.value = (quiet ? 0.55 : 1) * (1 - scrollK * 0.4);
    composer.render(dt);
    if (frames++ === 1) root.classList.add('gl-on');
    if (DEBUG && frames % 30 === 2) note('running, ' + geo.drawRange.count + ' of ' + N + ' particles, quality level ' + level + ', ' + Math.round(1 / Math.max(dt, 1e-3)) + ' fps');
    // Slow device? Step quality down: lower resolution first, then half the particles and no bloom.
    if (!reduce && frames > 30 && level < 2) {
      slow = slow * 0.95 + (dt > 1 / 40 ? 1 : 0) * 0.05;
      if (slow > 0.5) {
        level++; slow = 0;
        if (level === 1) { PR = 1; renderer.setPixelRatio(1); composer.setPixelRatio(1); pMat.uniforms.uPR.value = 1; starMat.uniforms.uPR.value = 1; layout(); }
        else { geo.setDrawRange(0, Math.floor(N / 2)); bloom.enabled = false; }
      }
    }
    raf = reduce && frames > 3 ? 0 : requestAnimationFrame(frame);
  }
  raf = requestAnimationFrame(frame);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
    else if (!raf && !reduce) { last = performance.now(); raf = requestAnimationFrame(frame); }
  });
  if (reduce) addEventListener('resize', () => { if (!raf) { frames = 0; raf = requestAnimationFrame(frame); } });
}

if (canvas) {
  try { start(); } catch (e) { note('error: ' + e.message); /* any WebGL trouble: keep the CSS backdrop */ }
}
