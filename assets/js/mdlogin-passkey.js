/**
 * Passkey - Frontend JavaScript
 * 
 * Handles passkey registration and authentication on the login page
 * 
 * @package MDLOGIN_Passkey
 * @version 1.0.0
 */

class MDPasskeyLogin {
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
     * Validate email format
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Initialize the plugin
     */
    async init() {
        if (!this.isSupported) {
            this.showMessage(mdPasskeyAjax.strings.notSupported, 'error');
            return;
        }

        this.bindEvents();
        this.createUI();
        
        // Check if user is logged in and get their info
        await this.checkCurrentUser();
        
        // Initialize required attributes based on current state
        this.initializeRequiredAttributes();
    }

    /**
     * Bind event listeners
     */
    bindEvents() {
        document.addEventListener('click', (e) => {
            if (e.target.id === 'mdlogin-register') {
                e.preventDefault();
                this.startRegistration();
            } else if (e.target.id === 'mdlogin') {
                e.preventDefault();
                this.startLogin();
            } else if (e.target.id === 'mdlogin-register-link') {
                e.preventDefault();
                this.toggleRegisterForm();
            }
        });

        // Handle username field visibility (only for non-logged-in users)
        document.addEventListener('click', (e) => {
            if (e.target.id === 'mdlogin-register' && !this.currentUser) {
                this.showUsernameField();
            } else if (e.target.id === 'mdlogin') {
                this.hideUsernameField();
            }
        });
    }

    /**
     * Create UI elements
     */
    createUI() {
        // Add status container
        const statusContainer = document.createElement('div');
        statusContainer.id = 'mdlogin-status';
        statusContainer.className = 'mdlogin-status';
        
        // Insert after login form
        const loginForm = document.querySelector('#loginform');
        if (loginForm) {
            loginForm.parentNode.insertBefore(statusContainer, loginForm.nextSibling);
        }
    }

    /**
     * Initialize required attributes based on current state
     */
    initializeRequiredAttributes() {
        // Check if registration form is visible
        const registerForm = document.querySelector('.mdlogin-register');
        if (registerForm) {
            const isVisible = registerForm.style.display !== 'none';
            const usernameInput = registerForm.querySelector('#mdlogin-username');
            
            if (usernameInput) {
                if (isVisible && !this.currentUser) {
                    // Form is visible and user is not logged in - add required
                    usernameInput.setAttribute('required', 'required');
                } else {
                    // Form is hidden or user is logged in - remove required
                    usernameInput.removeAttribute('required');
                }
            }
        }
        
        // Check if username field is visible (for legacy support)
        const usernameField = document.querySelector('.mdlogin-username-field');
        if (usernameField) {
            const isVisible = usernameField.style.display !== 'none';
            const usernameInput = usernameField.querySelector('#mdlogin-username');
            
            if (usernameInput) {
                if (isVisible && !this.currentUser) {
                    // Field is visible and user is not logged in - add required
                    usernameInput.setAttribute('required', 'required');
                } else {
                    // Field is hidden or user is logged in - remove required
                    usernameInput.removeAttribute('required');
                }
            }
        }
    }

    /**
     * Show username field
     */
    showUsernameField() {
        const usernameField = document.querySelector('.mdlogin-username-field');
        if (usernameField) {
            usernameField.style.display = 'block';
            // Add required attribute when showing the field
            const usernameInput = usernameField.querySelector('#mdlogin-username');
            if (usernameInput && !this.currentUser) {
                usernameInput.setAttribute('required', 'required');
            }
        }
    }

    /**
     * Hide username field
     */
    hideUsernameField() {
        const usernameField = document.querySelector('.mdlogin-username-field');
        if (usernameField) {
            usernameField.style.display = 'none';
            // Remove required attribute when hiding the field to prevent validation errors
            const usernameInput = usernameField.querySelector('#mdlogin-username');
            if (usernameInput) {
                usernameInput.removeAttribute('required');
            }
        }
    }

    /**
     * Toggle register form visibility
     */
    toggleRegisterForm() {
        const registerForm = document.querySelector('.mdlogin-register');
        const registerLink = document.getElementById('mdlogin-register-link');
        
        if (registerForm && registerLink) {
            const isVisible = registerForm.style.display !== 'none';
            
            if (isVisible) {
                // Hide the form
                registerForm.style.display = 'none';
                
                // Remove required attribute from hidden input to prevent validation errors
                const usernameInput = registerForm.querySelector('#mdlogin-username');
                if (usernameInput) {
                    usernameInput.removeAttribute('required');
                }
                
                // Restore the original link text based on user status and credential count
                if (this.currentUser) {
                    // User is logged in
                    if (this.credentialCount === 0) {
                        registerLink.textContent = mdPasskeyAjax.strings.registerNewPasskey || 'Register a new passkey?';
                    } else {
                        registerLink.textContent = `${mdPasskeyAjax.strings.addAnotherCredential || 'Add another passkey credential'} (${this.credentialCount}/${this.maxCredentials})`;
                    }
                } else {
                    // User is not logged in
                    registerLink.textContent = mdPasskeyAjax.strings.createNewAccount || 'Create new account with passkey?';
                }
            } else {
                // Show the form
                registerForm.style.display = 'block';
                registerLink.textContent = mdPasskeyAjax.strings.hideRegister || 'Hide registration form?';
                
                // Add required attribute back for non-logged-in users
                const usernameInput = registerForm.querySelector('#mdlogin-username');
                if (usernameInput && !this.currentUser) {
                    usernameInput.setAttribute('required', 'required');
                }
                
                // Focus on the username input
                if (usernameInput) {
                    usernameInput.focus();
                }
            }
        }
    }

    /**
     * Show status message
     * 
     * @param {string} message Message to display
     * @param {string} type Message type (success, error, info)
     * @param {object} errorData Additional error data (retry_after, error_code)
     */
    showMessage(message, type = 'info', errorData = null) {
        const statusContainer = document.getElementById('mdlogin-status');
        if (!statusContainer) return;

        // Remove existing type classes and data attributes
        statusContainer.classList.remove('success', 'error', 'info');
        statusContainer.removeAttribute('data-error-type');
        
        // Add new type class
        statusContainer.classList.add(type);
        statusContainer.style.display = 'block';
        
        // Handle rate limit errors with countdown
        if (errorData && errorData.error_code === 'rate_limit_exceeded' && errorData.retry_after) {
            this.showRateLimitMessage(statusContainer, message, errorData.retry_after);
        } else {
            statusContainer.textContent = message;
            
            // Add error type attribute for specific styling
            if (errorData && errorData.error_code) {
                statusContainer.setAttribute('data-error-type', errorData.error_code);
            }
        }

        // Auto-hide after 5 seconds (except for rate limit messages)
        if (!errorData || errorData.error_code !== 'rate_limit_exceeded') {
            setTimeout(() => {
                statusContainer.style.display = 'none';
            }, 5000);
        }
    }

    /**
     * Show rate limit message with countdown
     * 
     * @param {HTMLElement} container Status container element
     * @param {string} message Base error message
     * @param {number} retryAfter Seconds until retry is allowed
     */
    showRateLimitMessage(container, message, retryAfter) {
        let timeLeft = retryAfter;
        
        const updateMessage = () => {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            const timeString = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
            
            container.innerHTML = `
                <div class="mdlogin-rate-limit-message">
                    <div class="mdlogin-rate-limit-icon">⏰</div>
                    <div class="mdlogin-rate-limit-content">
                        <div class="mdlogin-rate-limit-title">Too Many Attempts</div>
                        <div class="mdlogin-rate-limit-text">${message}</div>
                        <div class="mdlogin-rate-limit-countdown">Please wait: <span class="mdlogin-countdown-timer">${timeString}</span></div>
                    </div>
                </div>
            `;
            
            if (timeLeft <= 0) {
                container.innerHTML = `
                    <div class="mdlogin-rate-limit-message">
                        <div class="mdlogin-rate-limit-icon">✅</div>
                        <div class="mdlogin-rate-limit-content">
                            <div class="mdlogin-rate-limit-title">Ready to Try Again</div>
                            <div class="mdlogin-rate-limit-text">You can now attempt the operation again.</div>
                        </div>
                    </div>
                `;
                container.setAttribute('data-error-type', 'rate_limit_exceeded');
                return;
            }
            
            timeLeft--;
            setTimeout(updateMessage, 1000);
        };
        
        updateMessage();
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
     * Convert ArrayBuffer to standard base64
     * 
     * @param {ArrayBuffer} value ArrayBuffer
     * @returns {string}
     */
    arrayBufferToBase64(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value)));
    }

    /**
     * Convert base64url to standard base64
     * 
     * @param {string} base64url Base64url string
     * @returns {string}
     */
    base64UrlToBase64(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        switch (base64.length % 4) {
            case 2: base64 += '=='; break;
            case 3: base64 += '='; break;
        }
        return base64;
    }

    /**
     * Check if user is logged in and get their info
     */
    async checkCurrentUser() {
        try {
            const response = await fetch(mdPasskeyAjax.restUrl + 'current-user', {
                method: 'GET',
                headers: {
                    'X-WP-Nonce': mdPasskeyAjax.nonce
                }
            });

            const data = await response.json();
            
            if (data.success && data.logged_in) {
                // User is logged in, store their info
                this.currentUser = data.user;
                this.userHasCredentials = data.has_credentials;
                this.credentialCount = data.credential_count || 0;
                this.maxCredentials = data.max_credentials || 5;
                this.canRegister = data.can_register || false;
                
                // Show register button if user can register more credentials
                if (this.canRegister) {
                    const registerButton = document.getElementById('mdlogin-register');
                    if (registerButton) {
                        registerButton.style.display = 'block';
                    }
                    
                    // Update description for logged-in users
                    const description = document.querySelector('.mdlogin-description');
                    if (description) {
                        description.textContent = mdPasskeyAjax.strings.registerForAccount;
                    }
                    
                    // Update register link text to show current count
                    const registerLink = document.getElementById('mdlogin-register-link');
                    if (registerLink) {
                        if (this.currentUser) {
                            // User is logged in
                            if (this.credentialCount === 0) {
                                registerLink.textContent = mdPasskeyAjax.strings.registerNewPasskey || 'Register a new passkey?';
                            } else {
                                registerLink.textContent = `${mdPasskeyAjax.strings.addAnotherCredential || 'Add another passkey credential'} (${this.credentialCount}/${this.maxCredentials})`;
                            }
                        } else {
                            // User is not logged in
                            registerLink.textContent = mdPasskeyAjax.strings.createNewAccount || 'Create new account with passkey?';
                        }
                    }
                } else {
                    // User has reached maximum credentials
                    this.showMessage(mdPasskeyAjax.strings.maxCredentialsReached || `You have reached the maximum limit of ${this.maxCredentials} passkey credentials.`, 'info');
                }
            }
        } catch (error) {
        }
    }

    /**
     * Start passkey registration
     */
    async startRegistration() {
        try {
            let username = '';
            let email = '';
            
            // If user is logged in, use their username or get optional input
            if (this.currentUser) {
                // Check if user provided additional input (username or email) for verification
                const inputValue = document.getElementById('mdlogin-username')?.value || '';
                if (inputValue) {
                    if (this.isValidEmail(inputValue)) {
                        email = inputValue;
                    } else {
                        username = inputValue;
                    }
                } else {
                    // No input provided, use current user's username
                    username = this.currentUser.username;
                }
            } else {
                // For users not logged in, check if they're providing existing user credentials or new user registration
                const inputValue = document.getElementById('mdlogin-username')?.value || '';
                if (!inputValue) {
                    this.showMessage(mdPasskeyAjax.strings.emailRequired, 'error');
                    return;
                }
                
                // Check if input looks like an email
                if (this.isValidEmail(inputValue)) {
                    email = inputValue;
                } else {
                    // If it's not an email, treat it as username (could be existing user)
                    username = inputValue;
                }
            }

            this.showMessage(mdPasskeyAjax.strings.startingRegistration, 'info');

            // Start registration process
            const formData = new URLSearchParams();
            if (username) {
                formData.append('username', username);
            }
            if (email) {
                formData.append('email', email);
            }
            

            
            const response = await fetch(mdPasskeyAjax.restUrl + 'start-registration', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-WP-Nonce': mdPasskeyAjax.nonce
                },
                body: formData.toString()
            });

            const data = await response.json();
            
            if (!data.success) {
                // Handle specific error messages
                if (data.error) {
                    // Check for rate limit errors
                    if (data.error_code === 'rate_limit_exceeded') {
                        this.showMessage(data.error, 'error', data);
                        return;
                    }
                    
                    // Check for specific error patterns
                    if (data.error.includes('already registered')) {
                        if (data.error.includes('Username')) {
                            throw new Error(mdPasskeyAjax.strings.usernameExists || data.error);
                        } else if (data.error.includes('Email')) {
                            throw new Error(mdPasskeyAjax.strings.emailExists || data.error);
                        }
                    }
                    if (data.error.includes('already have passkey credentials')) {
                        throw new Error(mdPasskeyAjax.strings.alreadyHasPasskey || data.error);
                    }
                    throw new Error(data.error);
                }
                throw new Error(mdPasskeyAjax.strings.error);
            }

            const options = data.options.publicKey;
            
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
                    // If there's an error processing excludeCredentials, remove them to prevent registration failure
                    options.excludeCredentials = [];
                }
            }

            this.showMessage(mdPasskeyAjax.strings.creatingPasskey, 'info');

            // Create credential
            const credential = await navigator.credentials.create({ publicKey: options });
            
            const credentialData = {
                id: credential.id, // Browser automatically converts to base64url
                type: credential.type,
                rawId: this.arrayBufferToBase64Url(credential.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64Url(credential.response.attestationObject)
                },
                session_id: data.session_id
            };

            // Verify registration
            const verifyResponse = await fetch(mdPasskeyAjax.restUrl + 'verify-registration', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': mdPasskeyAjax.nonce
                },
                body: JSON.stringify(credentialData)
            });

            const verifyResult = await verifyResponse.json();
            
            if (verifyResult.success) {
                // Show appropriate success message based on whether this was a new user
                const successMessage = verifyResult.is_new_user ? 
                    (mdPasskeyAjax.strings.newUserRegisterSuccess || 'Account created and passkey registered successfully! You can now login with your passkey.') :
                    mdPasskeyAjax.strings.registerSuccess;
                
                this.showMessage(successMessage, 'success');
                
                // Hide the registration form after successful registration
                const registerForm = document.querySelector('.mdlogin-register');
                const registerLink = document.getElementById('mdlogin-register-link');
                
                if (registerForm) {
                    registerForm.style.display = 'none';
                }
                
                // Clear the username field
                const usernameInput = document.getElementById('mdlogin-username');
                if (usernameInput) {
                    usernameInput.value = '';
                }
                
                // If this was a new user, refresh the page after a short delay to show login options
                if (verifyResult.is_new_user) {
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                } else {
                    // Refresh user data to get updated credential count
                    await this.checkCurrentUser();
                    
                    // Ensure the registration link text is updated correctly
                    const registerLink = document.getElementById('mdlogin-register-link');
                    if (registerLink) {
                        if (this.currentUser) {
                            // User is logged in
                            if (this.credentialCount === 0) {
                                registerLink.textContent = mdPasskeyAjax.strings.registerNewPasskey || 'Register a new passkey?';
                            } else {
                                registerLink.textContent = `${mdPasskeyAjax.strings.addAnotherCredential || 'Add another passkey credential'} (${this.credentialCount}/${this.maxCredentials})`;
                            }
                        } else {
                            // User is not logged in
                            registerLink.textContent = mdPasskeyAjax.strings.createNewAccount || 'Create new account with passkey?';
                        }
                    }
                }
            } else {
                // Check if this is a duplicate authenticator error
                if (verifyResult.error && verifyResult.error.includes('already have a passkey registered with')) {
                    this.showDuplicateAuthenticatorError(verifyResult);
                } else {
                    throw new Error(verifyResult.error || mdPasskeyAjax.strings.error);
                }
            }

        } catch (error) {
            
            // Check if this is a registration conflict error
            if (error.message && (error.message.includes('already registered') || error.message.includes('already exists'))) {
                this.showMessage(error.message, 'error', 'conflict');
            } else {
                this.showMessage(`${mdPasskeyAjax.strings.error}: ${error.message}`, 'error');
            }
        }
    }

    /**
     * Start passkey login
     */
    async startLogin() {
        try {
            this.showMessage(mdPasskeyAjax.strings.startingLogin, 'info');

            // Start login process
            const response = await fetch(mdPasskeyAjax.restUrl + 'start-login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-WP-Nonce': mdPasskeyAjax.nonce
                },
                body: ''
            });

            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || mdPasskeyAjax.strings.error);
            }

            const options = data.options.publicKey;
            options.challenge = this.base64ToArrayBuffer(options.challenge);
            
            // Process allowCredentials sequentially
            const processedCredentials = [];
            for (const credential of options.allowCredentials) {
                processedCredentials.push({
                    ...credential,
                    id: this.base64ToArrayBuffer(credential.id)
                });
            }
            options.allowCredentials = processedCredentials;

            this.showMessage(mdPasskeyAjax.strings.authenticating, 'info');

            // Get credential
            const credential = await navigator.credentials.get({ publicKey: options });
            
            const credentialData = {
                id: credential.id, // Browser automatically converts to base64url
                type: credential.type,
                rawId: this.arrayBufferToBase64Url(credential.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: this.arrayBufferToBase64Url(credential.response.authenticatorData),
                    signature: this.arrayBufferToBase64Url(credential.response.signature),
                    userHandle: credential.response.userHandle ? 
                        this.arrayBufferToBase64Url(credential.response.userHandle) : null
                },
                session_id: data.session_id
            };

            // Verify login
            const verifyResponse = await fetch(mdPasskeyAjax.restUrl + 'verify-login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': mdPasskeyAjax.nonce
                },
                body: JSON.stringify(credentialData)
            });

            const verifyResult = await verifyResponse.json();
            
            if (verifyResult.success) {
                // Show authenticator information if available
                if (verifyResult.authenticator_info) {
                    const authenticatorName = verifyResult.authenticator_info.name || 'Unknown Authenticator';
                    this.showMessage(`${mdPasskeyAjax.strings.loginSuccess} (${authenticatorName})`, 'success');
                } else {
                    this.showMessage(mdPasskeyAjax.strings.loginSuccess, 'success');
                }
                
                if (verifyResult.redirect_to) {
                    setTimeout(() => {
                        window.location.href = verifyResult.redirect_to;
                    }, 1000);
                }
            } else {
                throw new Error(verifyResult.error || mdPasskeyAjax.strings.error);
            }

        } catch (error) {
            
            // Check if this is the "no credentials found" error
            if (error.message && error.message.includes('No users with passkey credentials found')) {
                this.showNoCredentialsMessage();
            } else {
                this.showMessage(`${mdPasskeyAjax.strings.error}: ${error.message}`, 'error');
            }
        }
    }

    /**
     * Show no credentials message with registration option
     */
    showNoCredentialsMessage() {
        const statusContainer = document.getElementById('mdlogin-status');
        if (!statusContainer) return;

        // Remove existing type classes
        statusContainer.classList.remove('success', 'error', 'info');
        statusContainer.classList.add('info');
        statusContainer.style.display = 'block';
        
        // Create the message with registration link
        statusContainer.innerHTML = `
            <div class="mdlogin-no-credentials">
                <p>${mdPasskeyAjax.strings.noCredentialsFound || 'No users with passkey credentials found.'}</p>
            </div>
        `;
    }

    /**
     * Show duplicate authenticator error with suggestions
     */
    showDuplicateAuthenticatorError(verifyResult) {
        const statusContainer = document.getElementById('mdlogin-status');
        if (!statusContainer) return;

        // Remove existing type classes
        statusContainer.classList.remove('success', 'error', 'info');
        statusContainer.classList.add('error');
        statusContainer.style.display = 'block';
        
        let suggestionsHtml = '';
        if (verifyResult.suggested_authenticators && Array.isArray(verifyResult.suggested_authenticators)) {
            suggestionsHtml = `
                <div class="mdlogin-suggestions">
                    <p><strong>${mdPasskeyAjax.strings.suggestedAuthenticators || 'Suggested authenticators:'}</strong></p>
                    <ul>
                        ${verifyResult.suggested_authenticators.map(auth => `<li>${auth}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        statusContainer.innerHTML = `
            <div class="mdlogin-duplicate-authenticator">
                <p>${verifyResult.error}</p>
                ${suggestionsHtml}
            </div>
        `;
    }

    /**
     * Get nonce for specific action
     * 
     * @param {string} action Action name
     * @returns {Promise<string>}
     */
    async getNonce(action) {
        try {
            const nonceResponse = await fetch(mdPasskeyAjax.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_get_nonce&mdlogin_action=${action}&nonce=${mdPasskeyAjax.nonce}`
            });
            
            const nonceData = await nonceResponse.json();
            return nonceData.success ? nonceData.data.nonce : '';
        } catch (error) {
            return '';
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new MDPasskeyLogin();
}); 