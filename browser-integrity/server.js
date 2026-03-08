import express from 'express';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const SERVER_SECRET = process.env.VIGILUS_SECRET || crypto.randomBytes(32).toString('hex');

const CHALLENGE_TTL_MS = 300_000;
const TOKEN_TTL_MS = 3_600_000;
const CANVAS_WIDTH = 280;
const CANVAS_HEIGHT = 80;
const AUDIO_SLICE_LENGTH = 500;

const EMPTY_CANVAS_HASH = crypto
    .createHash('sha256')
    .update(Buffer.alloc(CANVAS_WIDTH * CANVAS_HEIGHT * 4, 0))
    .digest('hex');

const EMPTY_AUDIO_HASH = crypto
    .createHash('sha256')
    .update(Buffer.alloc(AUDIO_SLICE_LENGTH * 4, 0))
    .digest('hex');

const challenges = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [id, challenge] of challenges) {
        if (now > challenge.expiresAt) challenges.delete(id);
    }
}, 60_000);

app.use(express.json({ limit: '16kb' }));
app.use(express.static(join(__dirname, 'public')));

app.get('/challenge', (req, res) => {
    const id = crypto.randomUUID();
    const nonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;

    challenges.set(id, {
        nonce,
        expiresAt,
        consumed: false,
    });

    res.json({ id, nonce, expiresAt });
});

app.post('/verify', (req, res) => {
    const { id, signals, proof } = req.body;

    const challenge = challenges.get(id);
    if (!challenge) return res.status(400).json({ error: 'Unknown challenge' });

    if (challenge.consumed)
        return res.status(400).json({
            error: 'Challenge already used',
        });

    if (Date.now() > challenge.expiresAt) {
        challenges.delete(id);
        return res.status(400).json({ error: 'Challenge expired' });
    }

    challenge.consumed = true;

    const result = validateProofAndSignals(challenge.nonce, signals, proof);

    challenges.delete(id);

    if (!result.valid) return res.status(400).json({ error: result.reason });

    const token = signToken({ sub: id, iat: Date.now() });
    res.json({ token, expiresAt: Date.now() + TOKEN_TTL_MS });
});

function validateProofAndSignals(nonce, signals, proof) {
    if (!signals || !proof) return { valid: false, reason: 'Missing data' };

    if (typeof proof !== 'string' || !/^[0-9a-f]{64}$/.test(proof))
        return { valid: false, reason: 'Malformed proof' };

    const { canvasHash, audioHash, webglParams, apiFingerprint } = signals;

    const expectedProof = crypto
        .createHash('sha256')
        .update([nonce, canvasHash, audioHash, webglParams, apiFingerprint].join('|'))
        .digest('hex');

    if (!timingSafeHexEqual(proof, expectedProof))
        return { valid: false, reason: 'Proof mismatch' };

    if (!isValidSignalHash(canvasHash, EMPTY_CANVAS_HASH))
        return { valid: false, reason: 'Invalid canvas proof' };

    if (!isValidSignalHash(audioHash, EMPTY_AUDIO_HASH))
        return { valid: false, reason: 'Invalid audio proof' };

    if (!isPlausibleWebGL(webglParams)) return { valid: false, reason: 'Invalid WebGL data' };

    if (!isPlausibleFingerprint(apiFingerprint))
        return { valid: false, reason: 'Missing browser APIs' };

    return { valid: true };
}

function isValidSignalHash(hash, knownEmptyHash) {
    if (typeof hash !== 'string') return false;
    if (!/^[0-9a-f]{64}$/.test(hash)) return false;
    if (/^(.)\1+$/.test(hash)) return false;
    if (hash === knownEmptyHash) return false;
    return true;
}

function isPlausibleWebGL(paramsJSON) {
    try {
        const params = JSON.parse(paramsJSON);
        if (params.unavailable) return true;
        if (params.maxTextureSize < 1024) return false;
        if (params.maxRenderbufferSize < 512) return false;
        if (!params.vendor || !params.renderer) return false;
        return true;
    } catch {
        return false;
    }
}

function isPlausibleFingerprint(fingerprintJSON) {
    try {
        const fingerprint = JSON.parse(fingerprintJSON);
        return fingerprint.hasSubtleCrypto && fingerprint.hasCanvas && fingerprint.hasAudioContext;
    } catch {
        return false;
    }
}

function timingSafeHexEqual(proofA, proofB) {
    try {
        return crypto.timingSafeEqual(Buffer.from(proofA, 'hex'), Buffer.from(proofB, 'hex'));
    } catch {
        return false;
    }
}

function signToken(payload) {
    const payloadString = JSON.stringify(payload);
    const payloadEncoded = Buffer.from(payloadString).toString('base64url');
    const signature = crypto
        .createHmac('sha256', SERVER_SECRET)
        .update(payloadString)
        .digest('base64url');

    return `${payloadEncoded}.${signature}`;
}

export function verifyToken(req, res, next) {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });

    const parts = header.slice(7).split('.');
    if (parts.length !== 2) return res.status(401).json({ error: 'Malformed token' });

    const [payloadEncoded, signature] = parts;
    const payloadString = Buffer.from(payloadEncoded, 'base64url').toString();

    const expectedSignature = crypto
        .createHmac('sha256', SERVER_SECRET)
        .update(payloadString)
        .digest('base64url');

    const signatureBuffer = Buffer.from(signature, 'base64url');
    const expectedBuffer = Buffer.from(expectedSignature, 'base64url');

    if (
        signatureBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
    )
        return res.status(401).json({ error: 'Invalid token' });

    const payload = JSON.parse(payloadString);
    if (Date.now() > payload.iat + TOKEN_TTL_MS)
        return res.status(401).json({ error: 'Token expired' });

    req.challengeAuth = payload;
    next();
}

app.get('/protected', verifyToken, (req, res) => {
    res.json({
        message: 'Access granted — browser integrity verified',
        auth: req.challengeAuth,
    });
});

app.listen(PORT, () => {
    console.log(`Vigilus running on http://localhost:${PORT}`);
});
