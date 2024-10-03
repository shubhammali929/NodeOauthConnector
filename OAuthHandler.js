// backend/lib/OAuthHandler.js
const axios = require('axios');
const querystring = require('querystring');
const { generateCodeVerifier, generateCodeChallenge, verifyAndDecodeToken, generateState } = require('./utils');

class OAuthHandler {
    constructor(clientId, clientSecret, pemCertificate, baseUrl, redirectUri) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.pemCertificate = pemCertificate;
        this.baseUrl = baseUrl;
        this.redirectUri = redirectUri;
        this.state = null;
    }

    // Step 1: Generate and redirect to Authorization URL
    handleAuthorizationRedirect(req, res, grantType) {
        this.state = generateState(); 
        const params = {
            response_type: 'code',
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            state: this.state,
            scope: 'openid profile email',
        };

        if (grantType === 'pkce') {
            //adding code challenge and challenge method for pkce grant..
            console.log("generating code_verifier and code_challenge");
            const codeVerifier = generateCodeVerifier();
            const codeChallenge = generateCodeChallenge(codeVerifier);
            params.code_challenge = codeChallenge;
            params.code_challenge_method = 'S256';
            this.codeVerifier = codeVerifier; //storing codeVerifier for further verification 
        }

        const authUrl = `${this.baseUrl}moas/idp/openidsso?${querystring.stringify(params)}`;
        res.redirect(authUrl);
    }

    // Step 2: Exchange Authorization Code for Token
    async exchangeCodeForToken(code, grantType, receivedState) {
        if (receivedState !== this.state) {
            throw new Error('Invalid state parameter. Possible CSRF attack.');
        }
    
        const payload = {
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: this.redirectUri,
            client_id: this.clientId,
        };
    
        if (grantType === 'pkce' && this.codeVerifier) {
            payload.code_verifier = this.codeVerifier; // Add code_verifier for PKCE
        } else {
            payload.client_secret = this.clientSecret; // Add client_secret for normal OAuth flow
        }
    
        try {
            const response = await axios.post(`${this.baseUrl}moas/rest/oauth/token`, querystring.stringify(payload), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            });
    
            const tokenData = response.data;
    
            const user_data = await verifyAndDecodeToken(tokenData.id_token, this.pemCertificate);
    
            if (!user_data) {
                throw new Error('No user data found in token response.');
            }
    
            return user_data;
        } catch (error) {
            // Handle errors (including token request failure or decoding issue)
            throw new Error(`Failed to exchange code for token: ${error.message}`);
        }
    }


    async getUserInfoUsingPasswordGrant(username, password) {
        try {
            const payload = {
                grant_type: 'password',
                username: username,
                password: password,
                client_id: this.clientId,
                client_secret: this.clientSecret,
                scope : 'openid'
            };

            const response = await axios.post(this.baseUrl + 'moas/rest/oauth/token', querystring.stringify(payload), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            });
            const tokenData = response.data;
            const id_token = tokenData.id_token;

            const userInfo = await verifyAndDecodeToken(id_token, this.pemCertificate);
            return userInfo;

        } catch (error) {
            if (error.response) {
                console.error('Error response data:', error.response.data);
                console.error('Error status:', error.response.status);
                console.error('Error headers:', error.response.headers);
            } else {
                console.error('Error message:', error.message);
            }
            throw error;
        }
    }

    logout(req,res){
        const logoutUrl = `${this.baseUrl}moas/idp/oidc/logout?post_logout_redirect_uri=${this.redirectUri}`;
        res.redirect(logoutUrl);
    }
}

module.exports = OAuthHandler;
