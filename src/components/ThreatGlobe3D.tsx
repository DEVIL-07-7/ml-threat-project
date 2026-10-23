import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { RoomEnvironment } from "three/addons/environments/RoomEnvironment.js";

export interface GeoTelemetryData {
  origin_city: string;
  origin_country: string;
  country_code: string;
  origin_lat: number;
  origin_lng: number;
  asn: string;
  target_hub: string;
  target_lat: number;
  target_lng: number;
}

export interface GlobeThreatItem {
  queue_id: string;
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  source_feed: string;
  risk_score: number;
  verdict?: string;
  triage_status: string;
  triage_latency_ms?: number;
  geo?: GeoTelemetryData;
}

interface ThreatGlobe3DProps {
  triageQueue: GlobeThreatItem[];
  latestStreamedIoc: GlobeThreatItem | null;
  onSelectIoc?: (iocValue: string) => void;
  onPullNextNow?: () => void;
}

const FALLBACK_ORIGINS: GeoTelemetryData[] = [
  {
    origin_city: "Moscow",
    origin_country: "Russia",
    country_code: "RU",
    origin_lat: 55.7558,
    origin_lng: 37.6173,
    asn: "AS47541 Bulletproof Node",
    target_hub: "Singapore SOC (asia-southeast1)",
    target_lat: 1.3521,
    target_lng: 103.8198,
  },
  {
    origin_city: "Pyongyang",
    origin_country: "North Korea",
    country_code: "KP",
    origin_lat: 39.0392,
    origin_lng: 125.7625,
    asn: "AS131279 Star KP",
    target_hub: "Tokyo APAC-North SOC",
    target_lat: 35.6762,
    target_lng: 139.6503,
  },
  {
    origin_city: "Shanghai",
    origin_country: "China",
    country_code: "CN",
    origin_lat: 31.2304,
    origin_lng: 121.4737,
    asn: "AS4134 Chinanet Backbone",
    target_hub: "Virginia US-East SOC",
    target_lat: 38.8951,
    target_lng: -77.0364,
  },
  {
    origin_city: "Bucharest",
    origin_country: "Romania",
    country_code: "RO",
    origin_lat: 44.4268,
    origin_lng: 26.1025,
    asn: "AS9009 M247 Transit",
    target_hub: "Frankfurt EU-Central SOC",
    target_lat: 50.1109,
    target_lng: 8.6821,
  },
  {
    origin_city: "Tehran",
    origin_country: "Iran",
    country_code: "IR",
    origin_lat: 35.6892,
    origin_lng: 51.389,
    asn: "AS58224 TCI Node",
    target_hub: "Frankfurt EU-Central SOC",
    target_lat: 50.1109,
    target_lng: 8.6821,
  },
  {
    origin_city: "Amsterdam",
    origin_country: "Netherlands",
    country_code: "NL",
    origin_lat: 52.3676,
    origin_lng: 4.9041,
    asn: "AS60781 LeaseWeb Edge",
    target_hub: "Virginia US-East SOC",
    target_lat: 38.8951,
    target_lng: -77.0364,
  },
];

// Pre-allocated module-scope math helpers (Zero GC in animation loop)
const _vec3A = new THREE.Vector3();
const _vec3B = new THREE.Vector3();
const _upVec = new THREE.Vector3(0, 1, 0);
const _quat = new THREE.Quaternion();
const _scale = new THREE.Vector3(1, 1, 1);
const _mat4 = new THREE.Matrix4();
const _color = new THREE.Color();

const GLOBE_RADIUS = 2.15;
const MAX_ARCS = 16;

function latLngToVector3(lat: number, lng: number, radius: number, out: THREE.Vector3): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  out.set(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
  return out;
}

function createProceduralWorldTexture(maxAnisotropy: number): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 2048;
  canvas.height = 1024;
  const ctx = canvas.getContext("2d");

  if (ctx) {
    // Deep obsidian ocean field
    ctx.fillStyle = "#06080c";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Subtle lat/lon graticule grid
    ctx.strokeStyle = "rgba(255, 255, 255, 0.06)";
    ctx.lineWidth = 1;
    for (let x = 0; x <= canvas.width; x += 64) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y <= canvas.height; y += 64) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    // Equator & Tropics precision hairlines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.14)";
    ctx.beginPath();
    ctx.moveTo(0, canvas.height / 2);
    ctx.lineTo(canvas.width, canvas.height / 2);
    ctx.stroke();

    // Stylized Continental Landmass Polygons (Normalized equirectangular coordinates)
    const continents: Array<Array<[number, number]>> = [
      // North America
      [
        [0.08, 0.16],
        [0.24, 0.14],
        [0.31, 0.26],
        [0.26, 0.42],
        [0.19, 0.46],
        [0.13, 0.34],
      ],
      // South America
      [
        [0.26, 0.50],
        [0.35, 0.54],
        [0.37, 0.68],
        [0.31, 0.84],
        [0.27, 0.72],
      ],
      // Europe
      [
        [0.46, 0.16],
        [0.58, 0.14],
        [0.60, 0.28],
        [0.52, 0.33],
        [0.45, 0.28],
      ],
      // Africa
      [
        [0.45, 0.36],
        [0.58, 0.37],
        [0.62, 0.52],
        [0.56, 0.76],
        [0.49, 0.68],
        [0.44, 0.48],
      ],
      // Asia & Eurasia
      [
        [0.59, 0.14],
        [0.86, 0.16],
        [0.89, 0.34],
        [0.80, 0.48],
        [0.70, 0.46],
        [0.62, 0.34],
      ],
      // Australia
      [
        [0.77, 0.64],
        [0.88, 0.64],
        [0.90, 0.77],
        [0.79, 0.78],
      ],
      // Japan / East Asia Island Arc
      [
        [0.86, 0.27],
        [0.89, 0.29],
        [0.88, 0.35],
        [0.85, 0.33],
      ],
      // UK / North Atlantic
      [
        [0.46, 0.20],
        [0.49, 0.20],
        [0.49, 0.25],
        [0.46, 0.25],
      ],
    ];

    ctx.fillStyle = "#171c26";
    ctx.strokeStyle = "rgba(250, 250, 250, 0.34)";
    ctx.lineWidth = 2.2;

    for (const poly of continents) {
      ctx.beginPath();
      poly.forEach(([nx, ny], idx) => {
        const px = nx * canvas.width;
        const py = ny * canvas.height;
        if (idx === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      });
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }

    // High-density dot-matrix city/telemetry grid inside continents
    ctx.fillStyle = "rgba(255, 255, 255, 0.22)";
    for (let x = 12; x < canvas.width; x += 16) {
      for (let y = 12; y < canvas.height; y += 16) {
        const pixel = ctx.getImageData(x, y, 1, 1).data;
        if (pixel[0] > 18) {
          ctx.fillRect(x, y, 2.2, 2.2);
        }
      }
    }
  }

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = maxAnisotropy;
  tex.needsUpdate = true;
  return tex;
}

function createRadialContactShadowTexture(): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    const grad = ctx.createRadialGradient(128, 128, 12, 128, 128, 120);
    grad.addColorStop(0, "rgba(0, 0, 0, 0.85)");
    grad.addColorStop(0.55, "rgba(0, 0, 0, 0.35)");
    grad.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 256, 256);
  }
  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

export default function ThreatGlobe3D({
  triageQueue,
  latestStreamedIoc,
  onSelectIoc,
  onPullNextNow,
}: ThreatGlobe3DProps) {
  const canvasMountRef = useRef<HTMLDivElement | null>(null);
  const [dockCollapsed, setDockCollapsed] = useState(false);
  const [autoRotate, setAutoRotate] = useState(true);
  const [arcElevation, setArcElevation] = useState(0.55);
  const [activeCameraPreset, setActiveCameraPreset] = useState("global");
  const [selectedArcItem, setSelectedArcItem] = useState<GlobeThreatItem | null>(null);

  // Refs for mutable animation loop state (never tears down WebGL context)
  const autoRotateRef = useRef(autoRotate);
  const arcElevationRef = useRef(arcElevation);
  const cameraTargetPosRef = useRef<THREE.Vector3 | null>(null);
  const rebuildArcsRef = useRef<((items: GlobeThreatItem[], elev: number) => void) | null>(null);

  useEffect(() => {
    autoRotateRef.current = autoRotate;
  }, [autoRotate]);

  useEffect(() => {
    arcElevationRef.current = arcElevation;
    if (rebuildArcsRef.current) {
      rebuildArcsRef.current(triageQueue, arcElevation);
    }
  }, [arcElevation, triageQueue]);

  // Keyboard shortcut 'H' to toggle Collapsible Zen Dock
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (
        (e.key === "h" || e.key === "H") &&
        document.activeElement?.tagName !== "INPUT" &&
        document.activeElement?.tagName !== "TEXTAREA"
      ) {
        setDockCollapsed((prev) => !prev);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    const container = canvasMountRef.current;
    if (!container) return;

    const width = container.clientWidth || 960;
    const height = container.clientHeight || 540;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        powerPreference: "high-performance",
      });
    } catch {
      // Fallback 2D canvas if WebGL is unavailable in the browser environment
      const fallbackCanvas = createProceduralWorldTexture(1).image as HTMLCanvasElement;
      fallbackCanvas.style.width = "100%";
      fallbackCanvas.style.height = "100%";
      fallbackCanvas.style.objectFit = "cover";
      container.innerHTML = "";
      container.appendChild(fallbackCanvas);
      return;
    }

    // 1. Software-WebGL Guard inspected directly from active context (no loseContext warning)
    const isSoftwareGl = (() => {
      try {
        const gl = renderer.getContext();
        if (!gl) return true;
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
        const gpu = String(gl.getParameter(param) || "");
        return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
      } catch {
        return false;
      }
    })();

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x050505);
    scene.fog = new THREE.FogExp2(0x050505, 0.032);

    const camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 100);
    camera.position.set(0, 1.85, 6.35);

    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.12;
    renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);
    renderer.shadowMap.enabled = !isSoftwareGl;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;

    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    // 2. Mandatory Studio Environment Reflection (RoomEnvironment + PMREMGenerator)
    const pmremGenerator = new THREE.PMREMGenerator(renderer);
    const envTarget = pmremGenerator.fromScene(new RoomEnvironment(), 0.04);
    scene.environment = envTarget.texture;
    pmremGenerator.dispose();

    // 3. Balanced 3-Point Warm/Cool Studio Lighting Rig
    const hemiLight = new THREE.HemisphereLight(0xdbeafe, 0x090d16, 0.95);
    scene.add(hemiLight);

    const keyLight = new THREE.DirectionalLight(0xfff2e0, 2.1);
    keyLight.position.set(6, 7, 5);
    keyLight.castShadow = !isSoftwareGl;
    keyLight.shadow.camera.left = -4;
    keyLight.shadow.camera.right = 4;
    keyLight.shadow.camera.top = 4;
    keyLight.shadow.camera.bottom = -4;
    keyLight.shadow.bias = -0.0005;
    keyLight.shadow.normalBias = 0.02;
    scene.add(keyLight);

    const rimLight = new THREE.DirectionalLight(0x94a3b8, 1.45);
    rimLight.position.set(-6, 3, -5);
    scene.add(rimLight);

    // OrbitControls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = !isSoftwareGl;
    controls.dampingFactor = 0.05;
    controls.minDistance = 3.5;
    controls.maxDistance = 11.5;
    controls.enablePan = false;
    controls.addEventListener("start", () => {
      cameraTargetPosRef.current = null;
    });

    // 4. Composite 6-Part Procedural 3D Orbital Assembly (THREE.Group)
    const globeAssembly = new THREE.Group();
    scene.add(globeAssembly);

    // Part 1: Primary Silhouette — Procedural World Continents & Graticule Sphere
    const maxAniso = renderer.capabilities.getMaxAnisotropy();
    const worldTexture = createProceduralWorldTexture(maxAniso);
    const coreGeo = new THREE.SphereGeometry(GLOBE_RADIUS, 64, 64);
    const coreMat = new THREE.MeshStandardMaterial({
      map: worldTexture,
      roughness: 0.68,
      metalness: 0.24,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreMesh.castShadow = !isSoftwareGl;
    coreMesh.receiveShadow = !isSoftwareGl;
    globeAssembly.add(coreMesh);

    // Part 2: Secondary Read — Geodesic Wireframe Lattice Shell (with polygonOffset against Z-fighting)
    const wireBaseGeo = new THREE.IcosahedronGeometry(GLOBE_RADIUS + 0.018, 3);
    const wireGeo = new THREE.WireframeGeometry(wireBaseGeo);
    const wireMat = new THREE.LineBasicMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.08,
    });
    wireMat.polygonOffset = true;
    wireMat.polygonOffsetFactor = -1;
    wireMat.polygonOffsetUnits = -1;
    const wireMesh = new THREE.LineSegments(wireGeo, wireMat);
    globeAssembly.add(wireMesh);

    // Part 3: Secondary Read — Outer Optical Atmosphere Shell (depthWrite: false, renderOrder: 2)
    const atmoGeo = new THREE.SphereGeometry(GLOBE_RADIUS + 0.065, 48, 48);
    const atmoMat = new THREE.MeshPhysicalMaterial({
      color: 0xe2e8f0,
      roughness: 0.15,
      metalness: 0.05,
      transmission: isSoftwareGl ? 0 : 0.9,
      transparent: true,
      opacity: isSoftwareGl ? 0.1 : 0.32,
      ior: 1.45,
      thickness: 0.8,
      clearcoat: 1.0,
      depthWrite: false,
    });
    const atmoMesh = new THREE.Mesh(atmoGeo, atmoMat);
    atmoMesh.renderOrder = 2;
    globeAssembly.add(atmoMesh);

    // Part 4: Secondary Read — Brushed Titanium Equatorial & Polar Telemetry Gimbal Rings
    const gimbalGroup = new THREE.Group();
    const ringGeoA = new THREE.TorusGeometry(GLOBE_RADIUS + 0.42, 0.012, 16, 120);
    const ringMatA = new THREE.MeshStandardMaterial({
      color: 0xd4d4d8,
      metalness: 0.92,
      roughness: 0.18,
    });
    const equatorialRing = new THREE.Mesh(ringGeoA, ringMatA);
    equatorialRing.rotation.x = Math.PI / 2;
    gimbalGroup.add(equatorialRing);

    const ringGeoB = new THREE.TorusGeometry(GLOBE_RADIUS + 0.58, 0.008, 12, 120);
    const ringMatB = new THREE.MeshStandardMaterial({
      color: 0x71717a,
      metalness: 0.65,
      roughness: 0.45,
    });
    const inclinedRing = new THREE.Mesh(ringGeoB, ringMatB);
    inclinedRing.rotation.x = Math.PI / 3.1;
    inclinedRing.rotation.y = Math.PI / 6;
    gimbalGroup.add(inclinedRing);
    scene.add(gimbalGroup);

    // Contact Shadow Grounding Plane beneath the Orbital Assembly
    const shadowTex = createRadialContactShadowTexture();
    const shadowPlaneGeo = new THREE.PlaneGeometry(6.8, 6.8);
    const shadowPlaneMat = new THREE.MeshBasicMaterial({
      map: shadowTex,
      transparent: true,
      depthWrite: false,
      opacity: 0.48,
    });
    const shadowPlane = new THREE.Mesh(shadowPlaneGeo, shadowPlaneMat);
    shadowPlane.rotation.x = -Math.PI / 2;
    shadowPlane.position.y = -2.75;
    scene.add(shadowPlane);

    // Part 5: Accent Detail — InstancedMesh C2 Origin Spires & Traveling Ballistic Packet Pulses
    const spireGeo = new THREE.CylinderGeometry(0.016, 0.032, 0.16, 6);
    spireGeo.translate(0, 0.08, 0); // Pivot at bottom-center flush with globe surface
    const spireMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      roughness: 0.25,
      metalness: 0.8,
    });
    const spireInstanced = new THREE.InstancedMesh(spireGeo, spireMat, MAX_ARCS * 2);
    spireInstanced.frustumCulled = false;
    spireInstanced.instanceColor = new THREE.InstancedBufferAttribute(
      new Float32Array(MAX_ARCS * 2 * 3),
      3
    );
    globeAssembly.add(spireInstanced);

    const pulseGeo = new THREE.SphereGeometry(0.042, 12, 12);
    const pulseMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const pulseInstanced = new THREE.InstancedMesh(pulseGeo, pulseMat, MAX_ARCS);
    pulseInstanced.frustumCulled = false;
    pulseInstanced.instanceColor = new THREE.InstancedBufferAttribute(
      new Float32Array(MAX_ARCS * 3),
      3
    );
    globeAssembly.add(pulseInstanced);

    // Part 6: 3D Ballistic Attack Arcs Container
    const arcsGroup = new THREE.Group();
    globeAssembly.add(arcsGroup);

    let activeCurves: Array<{
      curve: THREE.QuadraticBezierCurve3;
      phaseOffset: number;
      speed: number;
      riskScore: number;
      item: GlobeThreatItem;
    }> = [];

    const buildArcsForQueue = (items: GlobeThreatItem[], elevationFactor: number) => {
      // Dispose old arc geometries
      while (arcsGroup.children.length > 0) {
        const child = arcsGroup.children[0] as THREE.Line;
        child.geometry?.dispose();
        if (Array.isArray(child.material)) child.material.forEach((m) => m.dispose());
        else child.material?.dispose();
        arcsGroup.remove(child);
      }
      activeCurves = [];

      const list = items.slice(0, MAX_ARCS);
      for (let i = 0; i < MAX_ARCS; i++) {
        const item = list[i];
        if (!item) {
          _scale.set(0, 0, 0);
          _mat4.compose(_vec3A.set(0, 0, 0), _quat.identity(), _scale);
          spireInstanced.setMatrixAt(i * 2, _mat4);
          spireInstanced.setMatrixAt(i * 2 + 1, _mat4);
          pulseInstanced.setMatrixAt(i, _mat4);
          continue;
        }

        const geo = item.geo || FALLBACK_ORIGINS[i % FALLBACK_ORIGINS.length];
        const startPos = latLngToVector3(
          geo.origin_lat,
          geo.origin_lng,
          GLOBE_RADIUS,
          new THREE.Vector3()
        );
        const endPos = latLngToVector3(
          geo.target_lat,
          geo.target_lng,
          GLOBE_RADIUS,
          new THREE.Vector3()
        );

        // Midpoint elevated above the sphere surface for a 3D ballistic trajectory
        const midPos = startPos
          .clone()
          .add(endPos)
          .multiplyScalar(0.5)
          .normalize()
          .multiplyScalar(GLOBE_RADIUS + 0.45 + elevationFactor * 0.85);

        const curve = new THREE.QuadraticBezierCurve3(startPos, midPos, endPos);
        const pts = curve.getPoints(44);
        const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);

        const isCritical = (item.risk_score || 0) >= 85;
        const arcColor = isCritical ? 0xffffff : 0x94a3b8;
        const lineMat = new THREE.LineBasicMaterial({
          color: arcColor,
          transparent: true,
          opacity: isCritical ? 0.85 : 0.45,
        });
        const arcLine = new THREE.Line(lineGeo, lineMat);
        arcsGroup.add(arcLine);

        // Position C2 origin spire flush & oriented along surface normal
        _vec3A.copy(startPos).normalize();
        _quat.setFromUnitVectors(_upVec, _vec3A);
        _scale.set(1, isCritical ? 1.45 : 1.0, 1);
        _mat4.compose(startPos, _quat, _scale);
        spireInstanced.setMatrixAt(i * 2, _mat4);
        _color.setHex(isCritical ? 0xffffff : 0xa1a1aa);
        spireInstanced.setColorAt(i * 2, _color);

        // Position SOC Target Hub spire
        _vec3A.copy(endPos).normalize();
        _quat.setFromUnitVectors(_upVec, _vec3A);
        _scale.set(1.2, 0.9, 1.2);
        _mat4.compose(endPos, _quat, _scale);
        spireInstanced.setMatrixAt(i * 2 + 1, _mat4);
        _color.setHex(0xe2e8f0);
        spireInstanced.setColorAt(i * 2 + 1, _color);

        pulseInstanced.setColorAt(i, _color.setHex(0xffffff));

        activeCurves.push({
          curve,
          phaseOffset: (i * 0.19) % 1,
          speed: isCritical ? 0.42 : 0.28,
          riskScore: item.risk_score || 75,
          item,
        });
      }

      spireInstanced.instanceMatrix.needsUpdate = true;
      if (spireInstanced.instanceColor) spireInstanced.instanceColor.needsUpdate = true;
      spireInstanced.computeBoundingSphere();

      pulseInstanced.instanceMatrix.needsUpdate = true;
      if (pulseInstanced.instanceColor) pulseInstanced.instanceColor.needsUpdate = true;
      pulseInstanced.computeBoundingSphere();
    };

    rebuildArcsRef.current = buildArcsForQueue;
    buildArcsForQueue(triageQueue, arcElevationRef.current);

    if (!isSoftwareGl) {
      renderer.compile(scene, camera);
    }

    // Raycasting on click to inspect closest C2 origin or SOC hub
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const onCanvasClick = (event: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObject(spireInstanced, false);
      if (hits.length > 0 && typeof hits[0].instanceId === "number") {
        const arcIdx = Math.floor(hits[0].instanceId / 2);
        const matched = activeCurves[arcIdx];
        if (matched?.item) {
          setSelectedArcItem(matched.item);
          if (onSelectIoc) onSelectIoc(matched.item.ioc_value);
        }
      }
    };
    renderer.domElement.addEventListener("click", onCanvasClick);

    // 5. Paced Animation Loop using performance.now() (Zero THREE.Clock deprecation warnings)
    const startTimeMs = performance.now();
    let prevTimeMs = startTimeMs;
    let frameId = 0;
    let disposed = false;

    function afterDraw(cb: () => void) {
      const gl = renderer.getContext() as WebGL2RenderingContext;
      if (!gl || typeof gl.fenceSync !== "function") {
        frameId = window.setTimeout(cb, 80);
        return;
      }
      const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
      gl.flush();
      const poll = () => {
        if (disposed) return;
        const state = sync && gl.getSyncParameter(sync, gl.SYNC_STATUS);
        if (state === gl.UNSIGNALED) {
          frameId = window.setTimeout(poll, 5);
        } else {
          if (sync) gl.deleteSync(sync);
          frameId = window.setTimeout(cb, 80);
        }
      };
      frameId = window.setTimeout(poll, 5);
    }

    function tick() {
      if (disposed) return;
      const nowMs = performance.now();
      const delta = Math.min((nowMs - prevTimeMs) / 1000, 0.1);
      prevTimeMs = nowMs;
      const elapsed = (nowMs - startTimeMs) / 1000;

      if (autoRotateRef.current) {
        globeAssembly.rotation.y += delta * 0.16;
      }
      equatorialRing.rotation.z = elapsed * 0.08;
      inclinedRing.rotation.z = -elapsed * 0.11;

      // Smooth exponential damping for camera theater transitions
      if (cameraTargetPosRef.current) {
        camera.position.x = THREE.MathUtils.damp(
          camera.position.x,
          cameraTargetPosRef.current.x,
          4.2,
          delta
        );
        camera.position.y = THREE.MathUtils.damp(
          camera.position.y,
          cameraTargetPosRef.current.y,
          4.2,
          delta
        );
        camera.position.z = THREE.MathUtils.damp(
          camera.position.z,
          cameraTargetPosRef.current.z,
          4.2,
          delta
        );
        if (camera.position.distanceToSquared(cameraTargetPosRef.current) < 0.002) {
          cameraTargetPosRef.current = null;
        }
      }

      // Advance traveling packet pulses along 3D ballistic arcs (Zero GC)
      for (let i = 0; i < activeCurves.length; i++) {
        const entry = activeCurves[i];
        const t = (elapsed * entry.speed + entry.phaseOffset) % 1;
        entry.curve.getPoint(t, _vec3B);
        _scale.setScalar(entry.riskScore >= 85 ? 1.25 : 0.9);
        _quat.identity();
        _mat4.compose(_vec3B, _quat, _scale);
        pulseInstanced.setMatrixAt(i, _mat4);
      }
      if (activeCurves.length > 0) {
        pulseInstanced.instanceMatrix.needsUpdate = true;
      }

      controls.update();
      renderer.render(scene, camera);

      if (isSoftwareGl) afterDraw(tick);
      else frameId = requestAnimationFrame(tick);
    }

    tick();

    const onResize = () => {
      if (!container || disposed) return;
      const w = container.clientWidth || 960;
      const h = container.clientHeight || 540;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener("resize", onResize);
    const resizeObserver =
      typeof ResizeObserver !== "undefined" ? new ResizeObserver(onResize) : null;
    resizeObserver?.observe(container);

    return () => {
      disposed = true;
      cancelAnimationFrame(frameId);
      clearTimeout(frameId);
      window.removeEventListener("resize", onResize);
      resizeObserver?.disconnect();
      renderer.domElement.removeEventListener("click", onCanvasClick);
      controls.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      worldTexture.dispose();
      wireBaseGeo.dispose();
      wireGeo.dispose();
      wireMat.dispose();
      atmoGeo.dispose();
      atmoMat.dispose();
      ringGeoA.dispose();
      ringMatA.dispose();
      ringGeoB.dispose();
      ringMatB.dispose();
      shadowPlaneGeo.dispose();
      shadowPlaneMat.dispose();
      shadowTex.dispose();
      spireGeo.dispose();
      spireMat.dispose();
      pulseGeo.dispose();
      pulseMat.dispose();
      envTarget.dispose();
      renderer.dispose();
    };
  }, []);

  const handleCameraPreset = (preset: string) => {
    setActiveCameraPreset(preset);
    if (preset === "global") {
      cameraTargetPosRef.current = new THREE.Vector3(0, 1.85, 6.35);
    } else if (preset === "apac") {
      cameraTargetPosRef.current = new THREE.Vector3(-4.2, 1.6, -3.6);
    } else if (preset === "eu_ru") {
      cameraTargetPosRef.current = new THREE.Vector3(1.8, 3.4, -4.4);
    } else if (preset === "americas") {
      cameraTargetPosRef.current = new THREE.Vector3(4.5, 2.1, 3.4);
    }
  };

  const activeInspection = selectedArcItem || latestStreamedIoc || triageQueue[0] || null;
  const activeGeo = activeInspection?.geo || FALLBACK_ORIGINS[0];

  return (
    <div
      className="console-surface"
      style={{
        padding: 0,
        overflow: "hidden",
        position: "relative",
        height: 560,
        background: "#050505",
      }}
    >
      {/* Dedicated Isolated WebGL Canvas Mount (Outside React HUD Siblings) */}
      <div
        ref={canvasMountRef}
        style={{
          width: "100%",
          height: "100%",
          position: "absolute",
          inset: 0,
          cursor: "grab",
        }}
      />

      {/* Minimal Top-Left Spec Readout (No backdrop-filter over WebGL, No pulsing dots) */}
      <div
        style={{
          position: "absolute",
          top: 20,
          left: 24,
          zIndex: 10,
          pointerEvents: "none",
          background: "rgba(5, 5, 5, 0.88)",
          border: "1px solid rgba(255, 255, 255, 0.12)",
          borderRadius: 12,
          padding: "14px 18px",
          maxWidth: 420,
        }}
      >
        <div
          style={{
            fontSize: "0.74rem",
            color: "var(--muted)",
            letterSpacing: "0.03em",
            marginBottom: 4,
          }}
        >
          3D WEBGL GLOBAL C2 TELEMETRY · /WS/THREAT-STREAM
        </div>
        <div style={{ fontSize: "1.05rem", fontWeight: 600, color: "var(--ink)" }}>
          Live Ballistic C2 Attack Arcs & ASN Origin Spires
        </div>
        {activeInspection && (
          <div
            className="mono-num"
            style={{
              marginTop: 8,
              paddingTop: 8,
              borderTop: "1px solid rgba(255, 255, 255, 0.08)",
              fontSize: "0.78rem",
              color: "var(--muted)",
              lineHeight: 1.5,
            }}
          >
            <div>
              Origin:{" "}
              <strong style={{ color: "var(--ink)" }}>
                {activeGeo.origin_city}, {activeGeo.country_code}
              </strong>{" "}
              ({activeGeo.origin_lat.toFixed(1)}°, {activeGeo.origin_lng.toFixed(1)}°) ·{" "}
              {activeGeo.asn}
            </div>
            <div>
              Target:{" "}
              <strong style={{ color: "var(--ink)" }}>{activeGeo.target_hub}</strong> · Risk{" "}
              <strong style={{ color: "var(--ink)" }}>{activeInspection.risk_score}/100</strong>
            </div>
            <div style={{ color: "var(--ink)", marginTop: 2 }}>
              IOC: {activeInspection.ioc_value}
            </div>
          </div>
        )}
      </div>

      {/* Unified Collapsible Bottom Control Dock (Zero Viewport Occlusion, No Side Panels) */}
      <div
        style={{
          position: "absolute",
          bottom: 16,
          left: "50%",
          transform: "translateX(-50%)",
          zIndex: 12,
          width: "min(920px, 94%)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <button
          type="button"
          onClick={() => setDockCollapsed((prev) => !prev)}
          style={{
            background: "rgba(11, 11, 11, 0.94)",
            color: "var(--muted)",
            border: "1px solid rgba(255, 255, 255, 0.14)",
            borderBottom: dockCollapsed ? "1px solid rgba(255, 255, 255, 0.14)" : "none",
            borderRadius: dockCollapsed ? 999 : "10px 10px 0 0",
            padding: "5px 14px",
            fontSize: "0.75rem",
            fontFamily: "inherit",
            cursor: "pointer",
          }}
        >
          {dockCollapsed ? "▴ Show 3D Globe Controls (H)" : "▾ Hide Controls · Cinema Mode (H)"}
        </button>

        {!dockCollapsed && (
          <div
            style={{
              width: "100%",
              background: "rgba(11, 11, 11, 0.95)",
              border: "1px solid rgba(255, 255, 255, 0.14)",
              borderRadius: 14,
              padding: "12px 18px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 12,
            }}
          >
            {/* Theater Camera Presets */}
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              {[
                { id: "global", label: "Global Orbit" },
                { id: "apac", label: "APAC / Singapore SOC" },
                { id: "eu_ru", label: "Europe / RU Nexus" },
                { id: "americas", label: "Americas SOC" },
              ].map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  className={`console-tab ${activeCameraPreset === preset.id ? "active" : ""}`}
                  style={{ padding: "6px 12px", fontSize: "0.76rem" }}
                  onClick={() => handleCameraPreset(preset.id)}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* Ballistic Trajectory Elevation Slider */}
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: "0.75rem", color: "var(--muted)", whiteSpace: "nowrap" }}>
                Arc Altitude
              </span>
              <input
                type="range"
                min="0.2"
                max="1.1"
                step="0.05"
                value={arcElevation}
                onChange={(e) => setArcElevation(parseFloat(e.target.value))}
                style={{ width: 90, accentColor: "#ffffff" }}
                aria-label="Ballistic Arc Altitude"
              />
            </div>

            {/* Rotation & Live Stream Trigger */}
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <button
                type="button"
                className="console-btn-ghost"
                style={{ padding: "6px 12px", fontSize: "0.76rem" }}
                onClick={() => setAutoRotate((prev) => !prev)}
              >
                {autoRotate ? "Pause Orbit" : "Resume Orbit"}
              </button>
              {onPullNextNow && (
                <button
                  type="button"
                  className="console-btn-pill"
                  style={{ padding: "6px 14px", fontSize: "0.76rem" }}
                  onClick={onPullNextNow}
                >
                  Launch Live C2 Arc
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
