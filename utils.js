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
async function verifyAndDecodeToken(token) {
    try {
        const pemCertificate = `-----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIKQ+V528e3nGaOL72XA
        avmL2HAXwdG5+0Cg2X+ezPfSn2U+DxbYOKFyHXfdCj4ocgF1MKk1ECUDhMlZ6vsl
        m7ZPuq9Nus6cYeBxSFdKXaC+vI0hpghkGwAl7a6YT4HAbZ3qs+T7My5gaeuXI1j+
        8KBOXK8VRDormzQlI0Q+qbfqUSMCNBMsknxFWfgxvvXSBqEOV2Yq0hbp+JSrsB1S
        9DefmvNmxUKLDQ65MmInZ7HqfE+ocWt6H0ba9zISCgjSEs4m0fY6fr99EhuQ9vKX
        GcxQfvu2qAOHz0te4yQ67xoUGWzMCmZG3TUTfYz+kFVCSJSrmSnTzkppffio7ooA
        owIDAQAB
        -----END PUBLIC KEY-----`;

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
