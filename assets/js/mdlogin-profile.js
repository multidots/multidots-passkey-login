/**
 * Passkey - Profile Page JavaScript
 * 
 * Handles passkey management on the WordPress user profile page
 * 
 * @package MDLOGIN_Passkey
 * @version 1.0.0
 */

class MDPasskeyProfile {
    /**
     * Constructor
     */
    constructor() {
        this.isSupported = this.checkSupport();
        this.init();
    }

    /**
     * Check if WebAuthn is supported
     * 
     * @returns {boolean}
     */
    checkSupport() {
        return window.PublicKeyCredential && 
               window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
               window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }

    /**
     * Initialize the plugin
     */
    async init() {
        if (!this.isSupported) {
            this.showMessage(mdPasskeyProfile.strings.notSupported, 'error');
            return;
        }

        this.bindEvents();
    }

    /**
     * Bind event listeners
     */
    bindEvents() {
        // Handle register button click
        document.addEventListener('click', (e) => {
            if (e.target.id === 'mdlogin-register-profile') {
                e.preventDefault();
                this.registerPasskey();
            }
        });

        // Handle delete credential buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('mdlogin-delete-credential')) {
                e.preventDefault();
                const credentialId = e.target.getAttribute('data-credential-id');
                if (credentialId) {
                    this.deletePasskey(credentialId);
                }
            }
        });
    }

    /**
     * Show status message
     * 
     * @param {string} message Message to display
     * @param {string} type Message type (success, error, info)
     */
    showMessage(message, type = 'info') {
        const statusContainer = document.getElementById('mdlogin-profile-status');
        if (!statusContainer) return;

        // Remove existing type classes
        statusContainer.classList.remove('success', 'error', 'info');
        
        // Add new type class
        statusContainer.classList.add(type);
        statusContainer.style.display = 'block';
        statusContainer.textContent = message;

        // Auto-hide after 5 seconds
        setTimeout(() => {
            statusContainer.style.display = 'none';
        }, 5000);
    }

    /**
     * Convert base64 to ArrayBuffer
     * 
     * @param {string} value Base64 string
     * @returns {ArrayBuffer}
     */
    base64ToArrayBuffer(value) {
        const binaryString = atob(value);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Convert ArrayBuffer to base64url
     * 
     * @param {ArrayBuffer} value ArrayBuffer
     * @returns {string}
     */
    arrayBufferToBase64Url(value) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(value)));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    /**
     * Load user credentials
     */
    async loadCredentials() {
        try {
            const response = await fetch(mdPasskeyProfile.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_profile_get_credentials&nonce=${mdPasskeyProfile.profileNonce}`
            });

            const data = await response.json();
            
            if (data.success) {
                this.displayCredentials(data.data.credentials);
            } else {
                this.showMessage(data.data.message || 'Failed to load credentials.', 'error');
            }
        } catch (error) {
            this.showMessage('Failed to load credentials.', 'error');
        }
    }

    /**
     * Display credentials in the UI
     * 
     * @param {Array} credentials Array of credential objects
     */
    displayCredentials(credentials) {
        const container = document.getElementById('mdlogin-credentials-list');
        if (!container) return;

        if (!credentials || credentials.length === 0) {
            container.innerHTML = '<p>' + (mdPasskeyProfile.strings.noCredentials || 'No passkeys found.') + '</p>';
            return;
        }

        let html = '<div class="mdlogin-credentials-grid">';
        
        credentials.forEach((credential, index) => {
            const icon = this.getAuthenticatorIcon(credential.authenticator_name || 'Unknown Authenticator');
            const date = credential.created_at ? new Date(credential.created_at).toLocaleDateString() : 'Unknown date';
            const credentialId = credential.credential_id || credential.id || 'Unknown ID';
            const displayId = credentialId.length > 20 ? credentialId.substring(0, 20) + '...' : credentialId;
            
            html += `
                <div class="mdlogin-credential-item">
                    <div class="mdlogin-credential-icon">
                        <span class="dashicons ${icon}"></span>
                    </div>
                    <div class="mdlogin-credential-info">
                        <h4>${credential.authenticator_name || 'Unknown Authenticator'}</h4>
                        <p>${mdPasskeyProfile.strings.registeredOn || 'Registered on'}: ${date}</p>
                        <p>${mdPasskeyProfile.strings.credentialId || 'ID'}: ${displayId}</p>
                    </div>
                    <div class="mdlogin-credential-actions">
                        <button type="button" 
                                class="button button-small mdlogin-delete-credential" 
                                data-credential-id="${credentialId}"
                                title="${mdPasskeyProfile.strings.deleteCredential || 'Delete this passkey'}">
                            <span class="dashicons dashicons-trash"></span>
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Get authenticator icon class
     * 
     * @param {string} authenticatorName Name of the authenticator
     * @returns {string} Icon class
     */
    getAuthenticatorIcon(authenticatorName) {
        const iconMap = {
            'Google Password Manager': 'dashicons-google',
            'iCloud Keychain': 'dashicons-apple',
            'Chrome on Mac': 'dashicons-chrome',
            'Chrome on Windows': 'dashicons-chrome',
            'Chrome on Android': 'dashicons-chrome',
            'Safari on Mac': 'dashicons-safari',
            'Safari on iOS': 'dashicons-safari',
            'Firefox': 'dashicons-firefox',
            'Edge': 'dashicons-edge',
            'Platform Authenticator': 'dashicons-admin-network',
            'External Security Key': 'dashicons-admin-network',
            'Unknown Authenticator': 'dashicons-admin-network'
        };

        return iconMap[authenticatorName] || 'dashicons-admin-network';
    }

    /**
     * Register new passkey
     */
    async registerPasskey() {
        try {
            this.showMessage(mdPasskeyProfile.strings.startingRegistration, 'info');

            // Start registration process
            const response = await fetch(mdPasskeyProfile.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_profile_register&nonce=${mdPasskeyProfile.profileNonce}`
            });

            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.data.message || mdPasskeyProfile.strings.error);
            }

            const options = data.data.options.publicKey;
            
            options.challenge = this.base64ToArrayBuffer(options.challenge);
            options.user.id = this.base64ToArrayBuffer(options.user.id);
            
            // Convert excludeCredentials IDs to ArrayBuffer
            if (options.excludeCredentials && Array.isArray(options.excludeCredentials)) {
                try {
                    options.excludeCredentials = options.excludeCredentials.map(credential => {
                        if (!credential.id) {
                            return null;
                        }
                        return {
                            ...credential,
                            id: this.base64ToArrayBuffer(credential.id)
                        };
                    }).filter(credential => credential !== null);
                } catch (error) {
                    options.excludeCredentials = [];
                }
            }

            this.showMessage(mdPasskeyProfile.strings.creatingPasskey, 'info');

            // Create credential
            const credential = await navigator.credentials.create({ publicKey: options });
            
            const credentialData = {
                id: credential.id,
                type: credential.type,
                rawId: this.arrayBufferToBase64Url(credential.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64Url(credential.response.attestationObject)
                },
                session_id: data.data.session_id
            };

            // Verify registration
            const formData = new URLSearchParams();
            formData.append('action', 'mdlogin_passkey_profile_verify');
            formData.append('nonce', mdPasskeyProfile.profileNonce);
            formData.append('credential_data', JSON.stringify(credentialData));

            const verifyResponse = await fetch(mdPasskeyProfile.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: formData.toString()
            });

            const verifyResult = await verifyResponse.json();
            
            if (verifyResult.success) {
                this.showMessage(mdPasskeyProfile.strings.registerSuccess, 'success');
                
                // Reload credentials list
                await this.loadCredentials();
                
                // Refresh the page to update the UI
                setTimeout(() => {
                    window.location.reload();
                }, 2000);
            } else {
                throw new Error(verifyResult.data.message || mdPasskeyProfile.strings.error);
            }

        } catch (error) {
            this.showMessage(`${mdPasskeyProfile.strings.error}: ${error.message}`, 'error');
        }
    }

    /**
     * Delete passkey
     * 
     * @param {string} credentialId Credential ID to delete
     */
    async deletePasskey(credentialId) {
        if (!confirm(mdPasskeyProfile.strings.confirmDelete)) {
            return;
        }

        try {
            const response = await fetch(mdPasskeyProfile.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_profile_delete&credential_id=${encodeURIComponent(credentialId)}&nonce=${mdPasskeyProfile.profileNonce}`
            });

            const data = await response.json();
            
            if (data.success) {
                this.showMessage(mdPasskeyProfile.strings.deleteSuccess, 'success');
                
                // Reload credentials list
                await this.loadCredentials();
                
                // Refresh the page to update the UI
                setTimeout(() => {
                    window.location.reload();
                }, 2000);
            } else {
                this.showMessage(data.data.message || 'Failed to delete passkey.', 'error');
            }
        } catch (error) {
            this.showMessage('Failed to delete passkey.', 'error');
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if we're on the profile page and the object exists
    if (typeof mdPasskeyProfile !== 'undefined') {
        window.wpPasskeyProfile = new MDPasskeyProfile();
    }
}); 