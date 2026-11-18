/* The pyrmi.com homepage backdrop: a restrained particle singularity (accretion disk, matter spiralling in, polar jets)
   behind the hero, and nowhere else. Every particle's path is worked out in the vertex shader from time alone, so
   there's no simulation pass. It starts only after the page is idle (text first), fades out as you scroll past the
   hero and stops drawing once it's gone, pauses when the tab is hidden, drops quality on slow devices, draws one still
   frame for reduced motion, skips itself on Save-Data, and leaves the CSS fallback in place when WebGL isn't there. */
import * as THREE from '../vendor/three-r170/three.module.min.js';
import { EffectComposer } from '../vendor/three-r170/addons/postprocessing/EffectComposer.js';
import { RenderPass } from '../vendor/three-r170/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from '../vendor/three-r170/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from '../vendor/three-r170/addons/postprocessing/OutputPass.js';
import { ShaderPass } from '../vendor/three-r170/addons/postprocessing/ShaderPass.js';

const canvas = document.getElementById('gl');
const root = document.documentElement;
// Add ?bg=debug to the address to see what the background is doing (for checking a device or a browser).
const DEBUG = /[?&]bg=debug\b/.test(location.search);
function note(msg) {
  if (!DEBUG) return;
  let el = document.getElementById('bg-debug');
  if (!el) { el = document.createElement('div'); el.id = 'bg-debug'; el.style.cssText = 'position:fixed;left:8px;bottom:8px;z-index:99;font:12px monospace;color:#fff;background:#000c;padding:4px 8px'; document.body.appendChild(el); }
  el.textContent = 'bg: ' + msg;
}

function start() {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const mobile = matchMedia('(pointer: coarse)').matches || Math.min(innerWidth, innerHeight) < 700;
  const N = mobile ? 11000 : 34000;
  let PR = Math.min(devicePixelRatio || 1, mobile ? 1.25 : 1.5);
  let BASE = 0.9; // how visible it is at the top of the page (set per width in layout())

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: 'low-power' });
  } catch (e) { note('no WebGL (' + e.message + ')'); return; } // no WebGL: the CSS backdrop stays
  renderer.debug.onShaderError = (gl, program, vs, fs) => note('shader error: ' + (gl.getShaderInfoLog(vs) || gl.getShaderInfoLog(fs) || gl.getProgramInfoLog(program) || '?').slice(0, 200));
  renderer.setPixelRatio(PR);
  renderer.setSize(innerWidth, innerHeight, false);
  renderer.toneMapping = THREE.NoToneMapping;
  // Cleared to true black: the canvas is screen-blended over the page (site.css), so black adds nothing and the page
  // colour behind the hero is exactly the page colour everywhere else; only the light shows.
  renderer.setClearColor(0x000000, 1);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(46, innerWidth / innerHeight, 0.1, 2000);

  // ---- particles: mostly neutral grey, heating to the signal red near the horizon -------------------------------
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
      uTime: { value: 0 }, uIntro: { value: 1 }, uSize: { value: mobile ? 56 : 44 }, uPR: { value: PR }, uIntensity: { value: mobile ? 0.28 : 0.18 },
      uColA: { value: new THREE.Color('#8d8c88') }, uColB: { value: new THREE.Color('#5d5c59') }, uHot: { value: new THREE.Color('#ff3d57') }, uCore: { value: new THREE.Color('#fff3ee') },
    },
    vertexShader: /* glsl */`
      attribute vec3 aA, aB; attribute vec2 aG;
      uniform float uTime, uIntro, uSize, uPR, uIntensity;
      uniform vec3 uColA, uColB, uHot, uCore;
      varying vec3 vColor;
      #define TAU 6.28318530718
      void main(){
        vec3 p; float heat; float fade=1.0; float t=uTime;
        if(aA.x<0.80){
          // accretion disk with Keplerian shear: inner orbits outrun outer ones
          float r=3.0+pow(aA.y,1.6)*16.5;
          float ang=aA.z*TAU + t*9.0/pow(r,1.5);
          float wob=aG.y*0.05*r*0.3;
          p=vec3(cos(ang)*(r+wob), aG.x*(0.03+0.02*r), sin(ang)*(r+wob));
          heat=smoothstep(8.0,3.0,r);
        } else if(aA.x<0.94){
          // matter spiralling in and vanishing at the horizon
          float life=fract(aA.y + t*0.03*(0.6+aB.x));
          float r=mix(26.0,2.4,pow(life,0.7));
          float ang=aA.z*TAU + (26.0-r)*0.32 + t*0.25;
          p=vec3(cos(ang)*r, aG.x*0.04*r, sin(ang)*r);
          heat=smoothstep(7.0,2.4,r);
          fade=smoothstep(2.4,3.6,r)*smoothstep(26.0,22.0,r);
        } else {
          // twin polar jets, faint
          float side=aB.x<0.5?-1.0:1.0;
          float k=fract(aB.y + t*0.05);
          float len=pow(k,0.75)*9.0;
          float rad=(0.15+len*0.05)*sqrt(aB.z);
          float ang=aA.y*TAU + len*0.35 - t*1.4*side;
          p=vec3(cos(ang)*rad, side*(2.2+len), sin(ang)*rad);
          heat=(1.0-k)*0.6;
          fade=smoothstep(1.0,0.6,k)*0.3;
        }
        // arrival: each particle settles in from slightly further out (short, and never in the way of reading)
        float ki=clamp((uIntro-aA.y*0.3)/0.7,0.0,1.0);
        float e=1.0-pow(1.0-ki,3.0);
        if(ki<1.0){
          float sw=(1.0-e)*1.6; float cs=cos(sw), sn=sin(sw);
          vec3 q=p*(1.0+(1.0-e)*1.8);
          p=vec3(q.x*cs-q.z*sn, q.y, q.x*sn+q.z*cs);
          fade*=e;
        }
        vec4 mv=modelViewMatrix*vec4(p,1.0);
        gl_Position=projectionMatrix*mv;
        gl_PointSize=uSize*uPR*(0.35+aB.z*aB.z*1.3)*fade/max(-mv.z,0.1);
        vec3 col=mix(uColA,uColB,aB.y);
        col=mix(col,uHot,smoothstep(0.15,0.8,heat));
        col=mix(col,uCore,smoothstep(0.85,1.0,heat)*0.7);
        vColor=col*(0.7+aA.y*0.5)*uIntensity*(1.0+heat*1.1)*fade;
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

  // ---- the horizon: a black sphere that hides what's behind it, and a thin photon ring facing the camera ----------
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(2.25, mobile ? 10 : 20), new THREE.ShaderMaterial({
    uniforms: { uRim: { value: new THREE.Color('#ff3d57') } },
    vertexShader: `varying vec3 vN, vV; void main(){ vec4 wp=modelMatrix*vec4(position,1.0); vN=normalize(mat3(modelMatrix)*normal); vV=normalize(cameraPosition-wp.xyz); gl_Position=projectionMatrix*viewMatrix*wp; }`,
    fragmentShader: `uniform vec3 uRim; varying vec3 vN, vV; void main(){ float f=pow(1.0-max(dot(normalize(vN),normalize(vV)),0.0),10.0); gl_FragColor=vec4(uRim*f*0.5,1.0); }`,
  }));
  scene.add(core);
  const ringMat = new THREE.ShaderMaterial({
    uniforms: { uRim: { value: new THREE.Color('#f3e6e2') }, uGlow: { value: 1 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv*2.0-1.0; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
    fragmentShader: `uniform vec3 uRim; uniform float uGlow; varying vec2 vUv;
      void main(){ float r=length(vUv);
        float ring=exp(-pow((r-0.47)/0.008,2.0))*0.75 + exp(-pow((r-0.47)/0.04,2.0))*0.05;
        gl_FragColor=vec4(uRim*ring*uGlow,1.0); }`,
    blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
  });
  const ring = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), ringMat);
  ring.scale.setScalar(2.25 * 2.3);
  scene.add(ring);

  // ---- a sparse, static star field ------------------------------------------------------------------------------
  const SN = mobile ? 500 : 1200;
  const sp = new Float32Array(SN * 3), ss = new Float32Array(SN);
  for (let i = 0; i < SN; i++) {
    const u = Math.random() * 2 - 1, th = Math.random() * Math.PI * 2, s = Math.sqrt(1 - u * u), r = 400 + Math.random() * 300;
    sp.set([s * Math.cos(th) * r, u * r, s * Math.sin(th) * r], i * 3);
    ss[i] = Math.pow(Math.random(), 6) * 3 + 0.6;
  }
  const sg = new THREE.BufferGeometry();
  sg.setAttribute('position', new THREE.BufferAttribute(sp, 3));
  sg.setAttribute('aSize', new THREE.BufferAttribute(ss, 1));
  const starMat = new THREE.ShaderMaterial({
    uniforms: { uPR: { value: PR } },
    vertexShader: `attribute float aSize; uniform float uPR; varying float vB;
      void main(){ vec4 mv=modelViewMatrix*vec4(position,1.0); gl_Position=projectionMatrix*mv; gl_PointSize=aSize*uPR; vB=0.18+aSize*0.12; }`,
    fragmentShader: `varying float vB; void main(){ vec2 c=gl_PointCoord-0.5; float d=dot(c,c); if(d>0.25) discard; gl_FragColor=vec4(vec3(0.85)*vB*exp(-d*18.0),1.0); }`,
    blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
  });
  scene.add(new THREE.Points(sg, starMat));

  // ---- post: a light bloom and a vignette, both in linear light, then one conversion to the screen (OutputPass
  // last, so the page colour behind the hero matches the page colour everywhere else) ------------------------------
  const composer = new EffectComposer(renderer);
  composer.setPixelRatio(PR);
  composer.setSize(innerWidth, innerHeight);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(innerWidth, innerHeight), 0.38, 0.25, 0.4);
  bloom.enabled = !mobile;
  composer.addPass(bloom);
  const finish = new ShaderPass({
    uniforms: { tDiffuse: { value: null } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }`,
    fragmentShader: `uniform sampler2D tDiffuse; varying vec2 vUv;
      void main(){ vec3 col=texture2D(tDiffuse,vUv).rgb; float d=length(vUv-0.5);
        col*=mix(0.3,1.0,smoothstep(0.8,0.2,d));
        gl_FragColor=vec4(col,1.0); }`,
  });
  composer.addPass(finish);
  composer.addPass(new OutputPass());

  // ---- layout: on wide screens it sits right of the hero text; on phones, low and behind it --------------------
  function layout() {
    const w = innerWidth, h = innerHeight;
    camera.aspect = w / h;
    if (w >= 900) camera.setViewOffset(w, h, -0.3 * w, 0.02 * h, w, h);
    else camera.setViewOffset(w, h, -0.12 * w, -0.28 * h, w, h);
    camera.updateProjectionMatrix();
    renderer.setSize(w, h, false);
    composer.setSize(w, h);
    bloom.resolution.set(w, h);
    // Where it can sit clear of the headline it can be brighter; behind text (phones, narrow windows) it stays faint.
    BASE = w >= 1280 ? 0.95 : w >= 900 ? 0.7 : 0.5;
    if (typeof readScroll === 'function' && ready) readScroll();
  }
  let ready = false;
  layout();
  addEventListener('resize', layout);

  // ---- motion: slow orbit and a little pointer parallax; fades out as the hero scrolls away -------------------
  const ptr = { x: 0, y: 0, tx: 0, ty: 0 };
  if (!reduce) addEventListener('pointermove', (e) => { ptr.tx = e.clientX / innerWidth - 0.5; ptr.ty = e.clientY / innerHeight - 0.5; }, { passive: true });
  let scrollK = 0;
  function readScroll() {
    scrollK = Math.min(1, scrollY / Math.max(innerHeight * 0.85, 1));
    root.style.setProperty('--gl-o', String(Math.max(0, BASE * (1 - scrollK))));
    if (scrollK < 1 && !raf && !document.hidden && !reduce) { last = performance.now(); raf = requestAnimationFrame(frame); }
  }

  const ARRIVE = reduce ? 0 : 1600, born = performance.now();
  const easeOut = (x) => 1 - Math.pow(1 - x, 3);
  let t = reduce ? 14 : 0, last = performance.now(), raf = 0, frames = 0, slow = 0, level = 0;
  function frame(now) {
    const dt = Math.min((now - last) / 1000, 1 / 20); last = now;
    if (!reduce) t += dt;
    ptr.x += (ptr.tx - ptr.x) * 0.04; ptr.y += (ptr.ty - ptr.y) * 0.04;
    const intro = ARRIVE ? Math.min(1, (now - born) / ARRIVE) : 1;
    pMat.uniforms.uIntro.value = intro;
    ringMat.uniforms.uGlow.value = intro * intro;
    const orbit = t * 0.03 + ptr.x * 0.35;
    const dist = 36 + scrollK * 6 + (1 - easeOut(intro)) * 8;
    const height = 7 + scrollK * 6 - ptr.y * 3;
    camera.position.set(Math.sin(orbit) * dist, height, Math.cos(orbit) * dist);
    camera.lookAt(0, 0, 0);
    ring.quaternion.copy(camera.quaternion);
    pMat.uniforms.uTime.value = t;
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
    // Stop drawing once the hero is scrolled away (readScroll starts it again), and after a few frames for reduced motion.
    raf = (reduce && frames > 3) || (scrollK >= 1 && intro >= 1) ? 0 : requestAnimationFrame(frame);
  }
  addEventListener('scroll', readScroll, { passive: true });
  readScroll(); ready = true;
  if (!raf) raf = requestAnimationFrame(frame);

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
    else if (!raf && !reduce && scrollK < 1) { last = performance.now(); raf = requestAnimationFrame(frame); }
  });
  if (reduce) addEventListener('resize', () => { if (!raf) { frames = 0; raf = requestAnimationFrame(frame); } });
}

const saveData = navigator.connection && navigator.connection.saveData;
if (canvas && !saveData) {
  // Text first: wait until the browser is idle (or a short timeout) before spinning up WebGL.
  const go = () => { try { start(); } catch (e) { note('error: ' + e.message); /* any WebGL trouble: keep the CSS backdrop */ } };
  if ('requestIdleCallback' in window) requestIdleCallback(go, { timeout: 1200 }); else setTimeout(go, 300);
}
