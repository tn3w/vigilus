# Browser Integrity Challenge

Browser integrity challenge that generates unforgeable, replay-resistant tokens using browser-only rendering APIs.

## Quick Start

```bash
npm install
npm start
# Open http://localhost:3000
```

Set `VIGILUS_SECRET` for persistent token signing (random secret generated at startup otherwise):

```bash
VIGILUS_SECRET=your-secret-here npm start
```

## How It Works

```
Browser                           Server
  │                                 │
  │  GET /challenge                 │
  │────────────────────────────────►│ Generate random nonce, store with TTL
  │  { id, nonce, expiresAt }       │
  │◄────────────────────────────────│
  │                                 │
  │  Render nonce on Canvas 2D      │
  │  Process nonce through Web Audio│
  │  Collect WebGL GPU params       │
  │  Collect browser API fingerprint│
  │  SHA-256 hash all signals       │
  │                                 │
  │  POST /verify                   │
  │  { id, signals, proof }         │
  │────────────────────────────────►│ Validate challenge freshness
  │                                 │ Verify proof integrity (SHA-256)
  │                                 │ Plausibility checks on signals
  │                                 │ Mark challenge as consumed
  │  { token, expiresAt }           │
  │◄────────────────────────────────│ Issue HMAC-signed access token
  │                                 │
  │  Authorization: Bearer <token>  │
  │────────────────────────────────►│ Verify token signature + expiry
  │  Protected resource             │
  │◄────────────────────────────────│
```

The server nonce is rendered directly onto the canvas and used to derive the audio oscillator frequency. This means each challenge produces **different pixels and different audio samples**, making the output unpredictable without actually running the rendering pipeline.

## Signals

| Signal          | What it proves                                                                   | Browser API                                   |
| --------------- | -------------------------------------------------------------------------------- | --------------------------------------------- |
| Canvas 2D       | Real pixel rendering with anti-aliasing, subpixel text, gradients, bezier curves | `getImageData()` on nonce-specific drawing    |
| Web Audio       | Real DSP pipeline with oscillator → compressor → analyser chain                  | `OfflineAudioContext.startRendering()`        |
| WebGL params    | GPU hardware characteristics (vendor, renderer, limits)                          | `getParameter()`, `WEBGL_debug_renderer_info` |
| API fingerprint | Browser capability gate (crypto, audio, WebGL, WebRTC, etc.)                     | Various `navigator` and `window` properties   |

### Why These Signals Are Hard to Forge

**Canvas**: The nonce changes gradient colors, text content, arc angles, and bezier control points. Anti-aliasing and font rasterization are GPU/driver-specific — the exact pixel values are unpredictable without running a real rendering engine. JSDOM/happy-dom return all-zero `ImageData` (detected by entropy checks and empty-buffer denylist).

**Audio**: `OfflineAudioContext` renders audio deterministically but with browser-specific floating-point behavior in the oscillator, compressor, and FFT nodes. The nonce-derived frequency changes the output per challenge. No polyfill can replicate the exact DSP pipeline without a full audio engine.

**WebGL**: Hardware parameters like `MAX_TEXTURE_SIZE`, `UNMASKED_RENDERER_WEBGL`, and extension counts reflect actual GPU. Made optional for browsers without WebGL support.

## Threat Model

| Attacker                            | Blocked        | Mechanism                                                           |
| ----------------------------------- | -------------- | ------------------------------------------------------------------- |
| HTTP client (curl, Python requests) | ✅             | No JavaScript execution — can't compute any signals                 |
| Node.js / Deno                      | ✅             | No Canvas, OfflineAudioContext, or WebGL APIs                       |
| JSDOM / happy-dom                   | ✅             | Stubbed canvas returns zero pixels → empty-hash denylist catches it |
| Headless Chrome (Puppeteer)         | ⚠️ Cost raised | Requires full browser with real GPU — expensive at scale            |
| Replay attack                       | ✅             | Single-use challenges deleted after first verification attempt      |
| Source code exposure                | ✅             | Security from browser API exclusivity, not obscurity                |

### Headless Chrome Note

Puppeteer with a real Chromium instance can pass this challenge because it runs a complete browser engine. The defense here is **economic**: running headless Chrome at scale is orders of magnitude more expensive than simple HTTP clients or Node.js scripts. Combine with rate limiting and behavioral analysis for defense in depth.

## Integration

### Protect a Server Endpoint

```javascript
import { verifyToken } from './server.js';

app.get('/api/data', verifyToken, (req, res) => {
    res.json({ sensitive: 'data' });
});
```

### Solve from a Client Page

```html
<script type="module">
    import { solveChallenge } from '/solver.js';

    const { token } = await solveChallenge();

    // Use token for authenticated requests
    const response = await fetch('/api/data', {
        headers: { Authorization: `Bearer ${token}` },
    });
</script>
```

### Custom Endpoints

```javascript
const { token } = await solveChallenge('/custom/challenge', '/custom/verify');
```

## Production Considerations

- **HTTPS required** — `crypto.subtle` is only available in secure contexts
- **Rate limiting** — add to `/challenge` endpoint to prevent nonce flooding
- **Persistent storage** — replace the in-memory `Map` with Redis for multi-instance deployments
- **Token TTL** — default 1 hour, configurable via `TOKEN_TTL_MS`
- **Challenge TTL** — default 5 minutes, configurable via `CHALLENGE_TTL_MS`
