// backend/lib/utils.js
const crypto = require('crypto'); // For PKCE generation
const { importSPKI, jwtVerify } = require('jose');

// Function to generate a state
function generateState() {
    return crypto.randomBytes(32).toString('hex');
}
// Function to generate a code verifier for PKCE
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('hex');
}

// Function to generate a code challenge based on the verifier
function generateCodeChallenge(verifier) {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Function to verify and decode the ID token using a public key
async function verifyAndDecodeToken(token, pemCertificate) {
    try {
        const publicKey = await importSPKI(pemCertificate, 'RS256');

        const { payload } = await jwtVerify(token, publicKey, {
            algorithms: ['RS256'],
        });

        return payload;

    } catch (error) {
        console.error('Error verifying and decoding token:', error.message);
        throw error;
    }
}

module.exports = {
    generateCodeVerifier,
    generateCodeChallenge,
    verifyAndDecodeToken,
    generateState
};
