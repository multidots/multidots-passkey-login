/**
 * Passkey - Admin JavaScript
 * 
 * Handles admin panel functionality for credential management
 * 
 * @package MDLOGIN_Passkey
 * @version 1.0.0
 */

class MDPasskeyAdmin {
    /**
     * Constructor
     */
    constructor() {
        this.init();
    }

    /**
     * Initialize the admin functionality
     */
    init() {
        this.bindEvents();
    }

    /**
     * Bind event listeners
     */
    bindEvents() {
        // Modal close button
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('mdlogin-modal-close')) {
                this.closeModal();
            }
        });

        // Close modal when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('mdlogin-modal')) {
                this.closeModal();
            }
        });

        // Delete credential button (for modal view)
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('delete-credential')) {
                e.preventDefault();
                this.deleteCredential(e.target.dataset.credentialId, e.target.dataset.userId);
            }
        });

        // WordPress handles bulk actions natively - no JavaScript needed
    }

    /**
     * View user credentials
     * 
     * @param {string} userId User ID
     */
    async viewCredentials(userId) {
        try {
            const response = await fetch(mdPasskeyAdmin.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_get_user_credentials&user_id=${userId}&nonce=${mdPasskeyAdmin.nonce}`
            });

            const data = await response.json();
            
            if (data.success) {
                this.showCredentialsModal(data.data);
            } else {
                alert(data.data.message || mdPasskeyAdmin.strings.loadError);
            }
        } catch (error) {
            // Handle error silently
            alert(mdPasskeyAdmin.strings.loadError);
        }
    }

    /**
     * Show credentials modal
     * 
     * @param {Object} data User and credentials data
     */
    showCredentialsModal(data) {
        const modal = document.getElementById('mdlogin-modal');
        const credentialsList = document.getElementById('mdlogin-credentials-list');
        
        if (!modal || !credentialsList) return;

        // Build credentials HTML
        let credentialsHtml = `
            <div class="mdlogin-user-info">
                <h3>${data.user.name} (${data.user.login})</h3>
                <p>User ID: ${data.user.id}</p>
            </div>
        `;

        if (data.credentials.length > 0) {
            credentialsHtml += '<div class="mdlogin-credentials-table">';
            credentialsHtml += '<table class="wp-list-table widefat fixed striped">';
            credentialsHtml += '<thead><tr>';
            credentialsHtml += '<th>Credential ID</th>';
            credentialsHtml += '<th>Type</th>';
            credentialsHtml += '<th>Transports</th>';
            credentialsHtml += '<th>Actions</th>';
            credentialsHtml += '</tr></thead><tbody>';

            data.credentials.forEach(credential => {
                credentialsHtml += '<tr>';
                credentialsHtml += `<td><code>${credential.id}</code></td>`;
                credentialsHtml += `<td>${credential.type}</td>`;
                credentialsHtml += `<td>${credential.transports.join(', ') || 'None'}</td>`;
                credentialsHtml += `<td>
                    <button class="button delete-credential" 
                            data-credential-id="${credential.id}" 
                            data-user-id="${data.user.id}">
                        Delete
                    </button>
                </td>`;
                credentialsHtml += '</tr>';
            });

            credentialsHtml += '</tbody></table></div>';
        } else {
            credentialsHtml += '<p>No credentials found for this user.</p>';
        }

        credentialsList.innerHTML = credentialsHtml;
        modal.style.display = 'block';
    }

    /**
     * Close modal
     */
    closeModal() {
        const modal = document.getElementById('mdlogin-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    /**
     * Delete credential
     * 
     * @param {string} credentialId Credential ID
     * @param {string} userId User ID
     */
    async deleteCredential(credentialId, userId) {
        if (!confirm(mdPasskeyAdmin.strings.confirmDelete)) {
            return;
        }

        try {
            const response = await fetch(mdPasskeyAdmin.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_delete_credential&credential_id=${credentialId}&user_id=${userId}&nonce=${mdPasskeyAdmin.nonce}`
            });

            const data = await response.json();
            
            if (data.success) {
                alert(mdPasskeyAdmin.strings.deleteSuccess);
                // Refresh the credentials view
                this.viewCredentials(userId);
            } else {
                alert(data.data.message || mdPasskeyAdmin.strings.deleteError);
            }
        } catch (error) {
            // Handle error silently
            alert(mdPasskeyAdmin.strings.deleteError);
        }
    }

    /**
     * Delete all credentials for a user
     * 
     * @param {string} userId User ID
     */
    async deleteAllCredentials(userId) {
        if (!confirm('Are you sure you want to delete ALL credentials for this user? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(mdPasskeyAdmin.ajaxUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=mdlogin_passkey_delete_all_credentials&user_id=${userId}&nonce=${mdPasskeyAdmin.nonce}`
            });

            const data = await response.json();
            
            if (data.success) {
                alert('All credentials deleted successfully.');
                // Refresh the page to update the table
                window.location.reload();
            } else {
                alert(data.data.message || 'Failed to delete all credentials.');
            }
        } catch (error) {
            // Handle error silently
            alert('Failed to delete all credentials.');
        }
    }

    // WordPress handles bulk actions natively through the list table
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new MDPasskeyAdmin();

    //Accordion in mobile
    function moveTabContent() {
        const tabContent = document.querySelector('.tab-content');
        const mainWrap = document.querySelector('.mdlogin-main-wrap');
        const activeTab = document.querySelector('.mdlogin-main-wrap .nav-tab-active');

        if (!tabContent || !mainWrap || !activeTab) return;
        // Wrap only if not already wrapped
        if (!activeTab.querySelector('span')) {
            const span = document.createElement('span');
            span.textContent = activeTab.textContent.trim();
            activeTab.textContent = ''; // Clear original text
            activeTab.appendChild(span);
        }
        if (window.innerWidth <= 767) {
            activeTab.appendChild(tabContent);
        } else {
            mainWrap.appendChild(tabContent);
        }
    }

    // Run on page load
    moveTabContent();

    // Run on window resize
    window.addEventListener('resize', moveTabContent);

    // Get the header element
    const stickyHeader = document.querySelector('.mdlogin-header');

    if (stickyHeader) {
        let lastKnownScrollY = 0;
        let ticking = false;

        window.addEventListener('scroll', () => {
            lastKnownScrollY = window.scrollY;

            if (!ticking) {
                window.requestAnimationFrame(() => {
                    if (lastKnownScrollY > 5) {
                        stickyHeader.classList.add('scrolled');
                    } else {
                        stickyHeader.classList.remove('scrolled');
                    }
                    ticking = false;
                });
                ticking = true;
            }
        });
    }

}); 