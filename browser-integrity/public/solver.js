const CANVAS_WIDTH = 280;
const CANVAS_HEIGHT = 80;
const AUDIO_SAMPLE_RATE = 44100;
const AUDIO_SLICE_START = 4500;
const AUDIO_SLICE_END = 5000;

async function sha256(data) {
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    const hash = await crypto.subtle.digest('SHA-256', buffer);

    return Array.from(new Uint8Array(hash))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
}

async function collectCanvasProof(nonce) {
    const canvas = document.createElement('canvas');
    canvas.width = CANVAS_WIDTH;
    canvas.height = CANVAS_HEIGHT;
    const context = canvas.getContext('2d');

    const gradient = context.createLinearGradient(0, 0, CANVAS_WIDTH, 0);
    gradient.addColorStop(0, `#${nonce.slice(0, 6)}`);
    gradient.addColorStop(1, `#${nonce.slice(6, 12)}`);
    context.fillStyle = gradient;
    context.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

    context.font = '14px Arial';
    context.textBaseline = 'alphabetic';
    context.fillStyle = '#069';
    context.fillText(`${nonce.slice(0, 16)}\u0394\u2117\u221E\uFB01\uFB02`, 2, 15);

    context.fillStyle = 'rgba(102, 204, 0, 0.7)';
    context.fillText(`${nonce.slice(16, 32)}\u0394\u2117\u221E\uFB01\uFB02`, 4, 17);

    const arcAngle = (parseInt(nonce.slice(0, 8), 16) % 628) / 100;
    context.beginPath();
    context.arc(140, 50, 25, 0, arcAngle);
    context.strokeStyle = '#f60';
    context.lineWidth = 2.5;
    context.stroke();

    context.beginPath();
    context.moveTo(10, 70);
    context.bezierCurveTo(
        parseInt(nonce.slice(8, 10), 16),
        parseInt(nonce.slice(10, 12), 16) % CANVAS_HEIGHT,
        CANVAS_WIDTH - parseInt(nonce.slice(12, 14), 16),
        parseInt(nonce.slice(14, 16), 16) % CANVAS_HEIGHT,
        270,
        70
    );
    context.stroke();

    const imageData = context.getImageData(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

    return sha256(imageData.data.buffer);
}

async function collectAudioProof(nonce) {
    const AudioContextClass = window.OfflineAudioContext || window.webkitOfflineAudioContext;

    const context = new AudioContextClass(1, AUDIO_SAMPLE_RATE, AUDIO_SAMPLE_RATE);

    const oscillator = context.createOscillator();
    const compressor = context.createDynamicsCompressor();

    const frequency = 200 + (parseInt(nonce.slice(0, 4), 16) % 800);
    oscillator.frequency.value = frequency;
    oscillator.type = 'triangle';

    compressor.threshold.value = -50;
    compressor.knee.value = 40;
    compressor.ratio.value = 12;
    compressor.attack.value = 0;
    compressor.release.value = 0.25;

    oscillator.connect(compressor);
    compressor.connect(context.destination);
    oscillator.start(0);

    const renderedBuffer = await context.startRendering();
    const channelData = renderedBuffer.getChannelData(0);
    const slice = channelData.slice(AUDIO_SLICE_START, AUDIO_SLICE_END);

    return sha256(slice.buffer);
}

function collectWebGLParams() {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

    if (!context) return JSON.stringify({ unavailable: true });

    const debugExtension = context.getExtension('WEBGL_debug_renderer_info');

    const params = {
        vendor: debugExtension
            ? context.getParameter(debugExtension.UNMASKED_VENDOR_WEBGL)
            : context.getParameter(context.VENDOR),
        renderer: debugExtension
            ? context.getParameter(debugExtension.UNMASKED_RENDERER_WEBGL)
            : context.getParameter(context.RENDERER),
        maxTextureSize: context.getParameter(context.MAX_TEXTURE_SIZE),
        maxRenderbufferSize: context.getParameter(context.MAX_RENDERBUFFER_SIZE),
        maxViewportDims: Array.from(context.getParameter(context.MAX_VIEWPORT_DIMS)),
        maxVertexAttribs: context.getParameter(context.MAX_VERTEX_ATTRIBS),
        maxVaryingVectors: context.getParameter(context.MAX_VARYING_VECTORS),
        aliasedLineWidthRange: Array.from(context.getParameter(context.ALIASED_LINE_WIDTH_RANGE)),
        aliasedPointSizeRange: Array.from(context.getParameter(context.ALIASED_POINT_SIZE_RANGE)),
        extensionCount: context.getSupportedExtensions()?.length ?? 0,
    };

    context.getExtension('WEBGL_lose_context')?.loseContext();

    return JSON.stringify(params);
}

function collectAPIFingerprint() {
    const fingerprint = {
        hasSubtleCrypto: !!crypto?.subtle,
        hasCanvas: !!document.createElement('canvas').getContext('2d'),
        hasAudioContext: !!(window.OfflineAudioContext || window.webkitOfflineAudioContext),
        hasWebGL: !!document.createElement('canvas').getContext('webgl'),
        hasWebRTC: !!window.RTCPeerConnection,
        hasServiceWorker: 'serviceWorker' in navigator,
        hasIndexedDB: !!window.indexedDB,
        hardwareConcurrency: navigator.hardwareConcurrency ?? 0,
        deviceMemory: navigator.deviceMemory ?? 0,
        maxTouchPoints: navigator.maxTouchPoints ?? 0,
        colorDepth: screen.colorDepth ?? 0,
        pixelRatio: window.devicePixelRatio ?? 0,
    };

    return JSON.stringify(fingerprint);
}

export async function solveChallenge(challengeUrl = '/challenge', verifyUrl = '/verify') {
    const challengeResponse = await fetch(challengeUrl);

    if (!challengeResponse.ok) throw new Error('Failed to fetch challenge');

    const { id, nonce } = await challengeResponse.json();

    const [canvasHash, audioHash] = await Promise.all([
        collectCanvasProof(nonce),
        collectAudioProof(nonce),
    ]);

    const webglParams = collectWebGLParams();
    const apiFingerprint = collectAPIFingerprint();

    const proof = await sha256(
        [nonce, canvasHash, audioHash, webglParams, apiFingerprint].join('|')
    );

    const verifyResponse = await fetch(verifyUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id,
            signals: {
                canvasHash,
                audioHash,
                webglParams,
                apiFingerprint,
            },
            proof,
        }),
    });

    if (!verifyResponse.ok) {
        const error = await verifyResponse.json();
        throw new Error(error.error || 'Verification failed');
    }

    return verifyResponse.json();
}
