<?php
/**
 * Plugin Loader Class
 * 
 * Handles frontend functionality, script enqueuing, and UI rendering
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * MDLOGIN_Passkey_Loader class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Loader {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_Loader
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_Loader
     */
    public static function mdlogin_get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        $this->mdlogin_init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function mdlogin_init_hooks() {
        // Enqueue scripts and styles
        add_action('login_enqueue_scripts', array($this, 'mdlogin_enqueue_scripts'));
        
        // Add passkey UI after login button using filter
        add_action('login_form', array($this, 'mdlogin_add_login_ui'));
        
        // Add nonce to login form
        add_action('login_form', array($this, 'mdlogin_add_nonce_field'));
        
        // AJAX handlers for nonce generation
        add_action('wp_ajax_mdlogin_get_nonce', array($this, 'mdlogin_get_nonce'));
        add_action('wp_ajax_nopriv_mdlogin_get_nonce', array($this, 'mdlogin_get_nonce'));
        
        // Clean up expired sessions
        add_action('mdlogin_passkey_cleanup', array($this, 'mdlogin_cleanup_expired_sessions'));
        
        // Schedule cleanup if not already scheduled
        if (!wp_next_scheduled('mdlogin_passkey_cleanup')) {
            wp_schedule_event(time(), 'hourly', 'mdlogin_passkey_cleanup');
        }
    }

    /**
     * Enqueue scripts and styles
     */
    public function mdlogin_enqueue_scripts() {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only enqueue if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return;
        }

        // Enqueue CSS
        wp_enqueue_style(
            'mdlogin',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/css/mdlogin-passkey.css',
            array(),
            MDLOGIN_PASSKEY_VERSION
        );

        // Enqueue JavaScript
        wp_enqueue_script(
            'mdlogin',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/js/mdlogin-passkey.js',
            array('jquery'),
            MDLOGIN_PASSKEY_VERSION,
            true
        );

        // Localize script with AJAX data
        wp_localize_script('mdlogin', 'mdPasskeyAjax', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'restUrl' => rest_url('mdlogin/v1/'),
            'nonce' => wp_create_nonce('wp_rest'),
            'strings' => array(
                'registerSuccess' => __('Your passkey has been registered successfully.', 'multidots-passkey-login'),
            'newUserRegisterSuccess' => __('Account created and passkey registered successfully! You can now login with your passkey.', 'multidots-passkey-login'),
                'loginSuccess' => __('You have logged in successfully.', 'multidots-passkey-login'),
                'error' => __('Something went wrong. Please try again.', 'multidots-passkey-login'),
                'notSupported' => __('Passkeys are not supported on this browser or device.', 'multidots-passkey-login'),
                'usernameRequired' => __('Enter a username or email to register your passkey.', 'multidots-passkey-login'),
            'emailRequired' => __('Username or email is required for registration.', 'multidots-passkey-login'),
            'usernameOrEmailRequired' => __('Username or email is required for new user registration.', 'multidots-passkey-login'),
            'invalidEmail' => __('Please enter a valid email address.', 'multidots-passkey-login'),
            'usernameExists' => __('This username is already registered. Please try a different username.', 'multidots-passkey-login'),
            'emailExists' => __('This email is already registered. Please login with your existing account or use a different email.', 'multidots-passkey-login'),
            'alreadyHasPasskey' => __('You already have passkey credentials registered. Please login with your existing passkey.', 'multidots-passkey-login'),
                'creatingPasskey' => __('Creating passkey… Please follow your device instructions.', 'multidots-passkey-login'),
                'authenticating' => __('Authenticating with passkey… Please follow your device instructions.', 'multidots-passkey-login'),
                'startingRegistration' => __('Initiating passkey registration…', 'multidots-passkey-login'),
                'startingLogin' => __('Initiating passkey login…', 'multidots-passkey-login'),
                'alreadyHasCredentials' => __('You already have passkey credentials linked to your account.', 'multidots-passkey-login'),
                'registerForAccount' => __('Register a new passkey or log in with an existing one.', 'multidots-passkey-login'),
                'noCredentialsFound' => __('No account with passkey credentials was found.', 'multidots-passkey-login'),
                'registerPrompt' => __('Already registered?', 'multidots-passkey-login'),
                'clickHere' => __('Click here', 'multidots-passkey-login'),
                'enterUsername' => __('Enter your username to register a passkey:', 'multidots-passkey-login'),
                'registerPasskey' => __('Register Passkey', 'multidots-passkey-login'),
                'cancel' => __('Cancel', 'multidots-passkey-login'),
                'haveRegistered' => __('Don\'t have a passkey yet? Register one here.', 'multidots-passkey-login'),
                'hideRegister' => __('Hide the registration form?', 'multidots-passkey-login'),
                'addAnotherCredential' => __('Add another passkey credential', 'multidots-passkey-login'),
                'registerNewPasskey' => __('Register a new passkey?', 'multidots-passkey-login'),
                'createNewAccount' => __('Create new account with passkey?', 'multidots-passkey-login'),
                'maxCredentialsReached' => __('You have reached the maximum number of passkey credentials.', 'multidots-passkey-login'),
                'duplicateAuthenticator' => __('This authenticator already has a registered passkey. Please use another authenticator.', 'multidots-passkey-login'),
                'suggestedAuthenticators' => __('Recommended authenticators:', 'multidots-passkey-login'),
            ),
            'settings' => array(
                'sessionTimeout' => isset($settings['session_timeout']) ? $settings['session_timeout'] : 300,
            )
        ));
    }


    /**
     * Add passkey UI to login form (legacy method)
     */
    public function mdlogin_add_login_ui() {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only show if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return;
        }
        
        // Check if user is logged in or new registrations are allowed
        $allow_new_registrations = isset($settings['allow_new_registrations']) ? $settings['allow_new_registrations'] : false;
        $show_registration = is_user_logged_in() || $allow_new_registrations;

        ?>
        <div class="mdlogin-container">
            <div role="separator" class="mdlogin-divider"><?php esc_html_e('or', 'multidots-passkey-login'); ?></div>
            <div class="mdlogin-buttons">
                <button type="button" id="mdlogin" class="mdlogin-button mdlogin-button-primary">
                    <span class="mdlogin-icon">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M9 3C7.067 3 5.5 4.567 5.5 6.5C5.5 8.433 7.067 10 9 10C10.933 10 12.5 8.433 12.5 6.5C12.5 4.567 10.933 3 9 3ZM7 6.5C7 5.39543 7.89543 4.5 9 4.5C10.1046 4.5 11 5.39543 11 6.5C11 7.60457 10.1046 8.5 9 8.5C7.89543 8.5 7 7.60457 7 6.5Z" fill="currentColor"></path>
                        <path d="M4.82727 14.9552C5.66915 13.4398 7.26644 12.5 8.99999 12.5C9.4142 12.5 9.74999 12.1642 9.74999 11.75C9.74999 11.3358 9.4142 11 8.99999 11C6.72169 11 4.62247 12.2352 3.51603 14.2268L3.07937 15.0128C2.58406 15.9043 3.22875 17 4.24867 17H10.25C10.6642 17 11 16.6642 11 16.25C11 15.8358 10.6642 15.5 10.25 15.5H4.52463L4.82727 14.9552Z" fill="currentColor"></path>
                        <path d="M15.125 12.5C15.6082 12.5 16 12.1082 16 11.625C16 11.1418 15.6082 10.75 15.125 10.75C14.6418 10.75 14.25 11.1418 14.25 11.625C14.25 12.1082 14.6418 12.5 15.125 12.5Z" fill="currentColor"></path>
                        <path fill-rule="evenodd" clip-rule="evenodd" d="M17.6745 14.8747C18.3217 14.4561 18.75 13.7281 18.75 12.9V11.625C18.75 9.62297 17.127 8 15.125 8C13.123 8 11.5 9.62297 11.5 11.625V12.9C11.5 13.8004 12.0064 14.5826 12.75 14.9772V16.8509C12.75 17.24 12.8635 17.6207 13.0766 17.9462L13.4986 18.591C14.1635 19.6068 15.5727 19.8007 16.4873 19.0023L17.0399 18.5198C17.7394 17.9091 17.9009 16.9369 17.5338 16.1584C17.7228 15.7633 17.7765 15.3088 17.6745 14.8747ZM14.2026 13.9609C14.1351 13.8353 14.0025 13.75 13.85 13.75C13.3806 13.75 13 13.3694 13 12.9V11.625C13 10.4514 13.9514 9.5 15.125 9.5C16.2986 9.5 17.25 10.4514 17.25 11.625V12.9C17.25 13.3694 16.8694 13.75 16.4 13.75H16.1818C15.9938 13.75 15.8301 13.8537 15.7447 14.0071C15.7202 14.051 15.7021 14.0991 15.6918 14.15C15.6853 14.1823 15.6818 14.2158 15.6818 14.25V14.3215C15.6818 14.4106 15.7056 14.4975 15.75 14.5736C15.7632 14.5961 15.7781 14.6177 15.7948 14.6381L16.1262 15.0431C16.1487 15.0706 16.1672 15.0998 16.1818 15.13C16.2004 15.1685 16.2129 15.2087 16.2194 15.2493C16.2497 15.4405 16.15 15.6426 15.9533 15.7227C15.8642 15.759 15.7958 15.8192 15.75 15.8915C15.6613 16.0314 15.657 16.2166 15.75 16.3612C15.7742 16.3988 15.8049 16.4336 15.8424 16.4642L16.0405 16.6256C16.2807 16.8213 16.2869 17.1861 16.0535 17.3898L15.5008 17.8723C15.2722 18.0719 14.9199 18.0234 14.7536 17.7695L14.3316 17.1247C14.2784 17.0434 14.25 16.9482 14.25 16.8509V14.15C14.25 14.0816 14.2328 14.0172 14.2026 13.9609Z" fill="currentColor"></path>
                        </svg>
                     </span>
                    <?php esc_html_e('Sign in with a passkey', 'multidots-passkey-login'); ?>
                </button>
            </div>
            <!-- Status messages -->
            <div id="mdlogin-status" class="mdlogin-status" style="display: none;"></div>
        </div>
        <?php
    }

    public function mdlogin_add_login_ui_bkp() {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only show if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return;
        }

        ?>
        <div class="mdlogin-container">
            <h3 class="mdlogin-title">
                <?php esc_html_e('Passkey Authentication', 'multidots-passkey-login'); ?>
            </h3>
            
            <div class="mdlogin-buttons">
                <button type="button" id="mdlogin-register" class="mdlogin-button mdlogin-button-secondary">
                    <span class="mdlogin-icon">🔑</span>
                    <?php esc_html_e('Register Passkey', 'multidots-passkey-login'); ?>
                </button>
                
                <button type="button" id="mdlogin" class="mdlogin-button mdlogin-button-primary">
                    <span class="mdlogin-icon">🔐</span>
                    <?php esc_html_e('Login with Passkey', 'multidots-passkey-login'); ?>
                </button>
            </div>
            
            <p class="mdlogin-description">
                <?php esc_html_e('Use your device\'s biometric authentication or PIN for secure login', 'multidots-passkey-login'); ?>
            </p>
            
            <!-- Username field for registration -->
            <div class="mdlogin-username-field" style="display: none;">
                <input 
                    type="text" 
                    id="mdlogin-username" 
                    placeholder="<?php esc_attr_e('Enter username for passkey registration', 'multidots-passkey-login'); ?>"
                    class="mdlogin-input"
                >
            </div>
            
            <!-- Status messages -->
            <div id="mdlogin-status" class="mdlogin-status" style="display: none;"></div>
        </div>
        <?php
    }

    /**
     * Add nonce field to login form
     */
    public function mdlogin_add_nonce_field() {
        wp_nonce_field('mdlogin_passkey', 'mdlogin_passkey_nonce');
    }

    /**
     * AJAX handler for nonce generation
     */
    public function mdlogin_get_nonce() {
        // Verify the request
        if (! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'wp_rest'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }

        $action = isset( $_POST['mdlogin_action'] )
            ? sanitize_text_field( wp_unslash( $_POST['mdlogin_action'] ) )
            : '';
        if (empty($action)) {
            wp_send_json_error(array(
                'message' => __('Invalid action.', 'multidots-passkey-login')
            ));
        }

        // Generate nonce for the specific action
        $nonce = wp_create_nonce($action);
        
        wp_send_json_success(array(
            'nonce' => $nonce
        ));
    }

    /**
     * Clean up expired sessions
     *
     * @return int Number of sessions deleted
     */
    public function mdlogin_cleanup_expired_sessions() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';
        
        // Get count before deletion
        // @codingStandardsIgnoreStart
        $count_before = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i", $table_name));
        
        // Delete expired sessions
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE expires_at < %s",
                current_time('mysql')
            )
        );
        
        // Get count after deletion using prepared statement
        $count_after = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i", $table_name));
        // @codingStandardsIgnoreEnd
        
        $deleted_count = $count_before - $count_after;
        

        
        return $deleted_count;
    }

    /**
     * Store session data in database with enhanced security
     *
     * @param string $session_id Session ID
     * @param int $user_id User ID
     * @param string $challenge Challenge data
     * @param array $options_data Options data
     * @return bool
     */
    public function mdlogin_store_session($session_id, $user_id, $challenge, $options_data) {
        global $wpdb;
        
        // Validate inputs
        if (empty($session_id) || !is_string($session_id) || strlen($session_id) !== 36) {
            return false;
        }
        
        if (!is_numeric($user_id) || $user_id < 0) {
            return false;
        }
        
        if (empty($challenge) || !is_string($challenge)) {
            return false;
        }
        
        if (!is_array($options_data)) {
            return false;
        }
        
        // Ensure the table exists
        $this->mdlogin_ensure_table_exists();
        
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';
        $settings = get_option('mdlogin_passkey_settings', array());
        $timeout = isset($settings['session_timeout']) ? absint($settings['session_timeout']) : 300;
        
        // Validate timeout range
        if ($timeout < 60 || $timeout > 3600) {
            $timeout = 300; // Default to 5 minutes
        }
        
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }
        
        // Increase timeout for WP Engine servers to account for potential delays
        if ( defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false ) {    
            $timeout = max($timeout, 600); // Minimum 10 minutes for WP Engine
        }
        
        $expires_at = gmdate( 'Y-m-d H:i:s', time() + $timeout );
        
        // For WP Engine, ensure we're using the master database for writes
        $is_wp_engine = defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false;
        if ($is_wp_engine) {
            $this->mdlogin_ensure_master_connection();
        }
        
        // Enhanced security metadata with session binding
        $client_ip = $this->mdlogin_get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $session_fingerprint = $this->mdlogin_generate_session_fingerprint($client_ip, $user_agent);
        
        $secure_options_data = array_merge($options_data, array(
            'ip_address' => $client_ip,
            'user_agent' => $user_agent,
            'created_at' => current_time('mysql'),
            'csrf_token' => wp_create_nonce('mdlogin_session_' . $user_id),
            'session_fingerprint' => $session_fingerprint,
            'session_binding' => hash('sha256', $client_ip . $user_agent . $user_id),
            'security_level' => $this->mdlogin_calculate_security_level($client_ip, $user_agent)
        ));
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom session table requires direct database access
        $result = $wpdb->insert(
            $table_name,
            array(
                'session_id' => $session_id,
                'user_id' => $user_id,
                'challenge' => base64_encode($challenge), // Encode binary data as base64
                'options_data' => wp_json_encode($secure_options_data),
                'expires_at' => $expires_at
            ),
            array('%s', '%d', '%s', '%s', '%s')
        );
        
        if ($result === false) {
            return false;
        }
        
        // For WP Engine, also store as a transient as backup
        if ($is_wp_engine) {
            $transient_key = 'mdlogin_passkey_session_' . $session_id;
            $transient_data = array(
                'user_id' => $user_id,
                'challenge' => base64_encode($challenge),
                'options_data' => $secure_options_data,
                'expires_at' => $expires_at
            );
            
            set_transient($transient_key, $transient_data, $timeout);
        }
        
        // For WP Engine, verify the session was stored by immediately trying to retrieve it
        if ($is_wp_engine) {
            $verification_attempts = 0;
            $max_verification_attempts = 3;
            
            while ($verification_attempts < $max_verification_attempts) {
                $verification_attempts++;
                usleep(100000); // Wait 0.1 seconds
                // @codingStandardsIgnoreStart
                $stored_session = $wpdb->get_row(
                    $wpdb->prepare(
                        "SELECT session_id FROM {$table_name} WHERE session_id = %s",
                        $session_id
                    ),
                    ARRAY_A
                );
                // @codingStandardsIgnoreEnd
                
                if ($stored_session) {
                    break;
                }
            }
        }
        
        return true;
    }

    /**
     * Get session data from database
     *
     * @param string $session_id Session ID
     * @return array|false Session data or false if not found/expired
     */
    public function mdlogin_get_session($session_id) {
        global $wpdb;
        
        // Ensure the table exists
        $this->mdlogin_ensure_table_exists();
        
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';

        // Check if we're on WP Engine
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }

        $is_wp_engine = defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false;
        
        // For WP Engine, try multiple attempts with delays to handle replication delays
        $max_attempts = $is_wp_engine ? 3 : 1;
        $attempt = 0;
        
        while ($attempt < $max_attempts) {
            $attempt++;

            // Force use of master database on WP Engine
            if ($is_wp_engine && $attempt > 1) {
                // Switch to master database for subsequent attempts
                $wpdb->use_mysqli = true;

            }

            // @codingStandardsIgnoreStart
            $session = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT * FROM {$table_name} WHERE session_id = %s AND expires_at > %s",
                    $session_id,
                    current_time( 'mysql' )
                ),
                ARRAY_A
            );
            // @codingStandardsIgnoreEnd

            if ($session) {
                // Decode the challenge from base64 back to binary
                $session['challenge'] = base64_decode($session['challenge']);
                $session['options_data'] = json_decode($session['options_data'], true);
                return $session;
            }
            
            // If this is WP Engine and we haven't found the session, wait and try again
            if ($is_wp_engine && $attempt < $max_attempts) {
                $delay = $attempt * 500000; // 0.5s, 1s delays
                usleep($delay);
            }
        }
        

        
        // For WP Engine, try transient backup if database lookup failed
        if ($is_wp_engine) {
            $transient_key = 'mdlogin_passkey_session_' . $session_id;
            $transient_data = get_transient($transient_key);
            
            if ($transient_data) {
                
                // Convert transient data to session format
                $session = array(
                    'session_id' => $session_id,
                    'user_id' => $transient_data['user_id'],
                    'challenge' => base64_decode($transient_data['challenge']),
                    'options_data' => $transient_data['options_data'],
                    'expires_at' => $transient_data['expires_at']
                );
                
                return $session;
            }
        }
        
        return false;
    }

    /**
     * Delete session from database
     *
     * @param string $session_id Session ID
     * @return bool
     */
    public function mdlogin_delete_session($session_id) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom session table requires direct database access
        $result = $wpdb->delete(
            $table_name,
            array('session_id' => $session_id),
            array('%s')
        );
        
        // Also delete transient backup for WP Engine
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }

        $is_wp_engine = defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false;
        if ($is_wp_engine) {
            $transient_key = 'mdlogin_passkey_session_' . $session_id;
            delete_transient($transient_key);
            

        }
        

        
        return $result !== false;
    }

    /**
     * Ensure the sessions table exists
     */
    private function mdlogin_ensure_table_exists() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';
        
        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom session table requires direct database access
        $table_exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        ); 
        
        if (!$table_exists) {
            
            // Create the table
            $this->mdlogin_create_sessions_table();
        }
    }

    /**
     * Create the sessions table
     */
    private function mdlogin_create_sessions_table() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        $table_name = $wpdb->prefix . 'mdlogin_passkey_sessions';
        
        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            session_id varchar(255) NOT NULL,
            user_id bigint(20) NOT NULL,
            challenge text NOT NULL,
            options_data longtext NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY session_id (session_id),
            KEY user_id (user_id),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
        

    }

    /**
     * Get client IP address securely
     *
     * @return string
     */
    private function mdlogin_get_client_ip() {
        $ip_keys = array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );

        foreach ( $ip_keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                // Sanitize and validate the header value before exploding
                $raw_ips = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                
                foreach ( explode( ',', $raw_ips ) as $ip ) {
                    $ip = trim( $ip );
                    // Validate IP address and exclude private/reserved ranges
                    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                        return $ip;
                    }
                }
            }
        }
        
        return isset( $_SERVER['REMOTE_ADDR'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
            : '0.0.0.0';
    }

    /**
     * Generate session fingerprint for enhanced security
     *
     * @param string $ip_address Client IP address
     * @param string $user_agent User agent string
     * @return string Session fingerprint
     */
    private function mdlogin_generate_session_fingerprint($ip_address, $user_agent) {
        $fingerprint_data = array(
            'ip' => $ip_address,
            'user_agent' => $user_agent,
            'accept_language' => isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'])) : '',
            'accept_encoding' => isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'])) : '',
            'connection' => isset($_SERVER['HTTP_CONNECTION']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_CONNECTION'])) : '',
            'timestamp' => time()
        );
        
        return hash('sha256', wp_json_encode($fingerprint_data));
    }

    /**
     * Calculate security level based on client characteristics
     *
     * @param string $ip_address Client IP address
     * @param string $user_agent User agent string
     * @return int Security level (1-5, higher is more secure)
     */
    private function mdlogin_calculate_security_level($ip_address, $user_agent) {
        $security_level = 1; // Base level
        
        // Check for VPN/Proxy indicators
        if ($this->mdlogin_is_suspicious_ip($ip_address)) {
            $security_level -= 1;
        }
        
        // Check for suspicious user agent patterns
        if ($this->mdlogin_is_suspicious_user_agent($user_agent)) {
            $security_level -= 1;
        }
        
        // Check for known good browsers
        if ($this->mdlogin_is_known_browser($user_agent)) {
            $security_level += 1;
        }
        
        // Check for mobile device (generally more secure)
        if ($this->mdlogin_is_mobile_device($user_agent)) {
            $security_level += 1;
        }
        
        // Ensure level is within bounds
        return max(1, min(5, $security_level));
    }

    /**
     * Check if IP address is suspicious
     *
     * @param string $ip_address IP address to check
     * @return bool True if suspicious
     */
    private function mdlogin_is_suspicious_ip($ip_address) {
        // Check for known VPN/proxy IP ranges (simplified check)
        $suspicious_patterns = array(
            '10.0.0.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (strpos($ip_address, $pattern) === 0) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if user agent is suspicious
     *
     * @param string $user_agent User agent string
     * @return bool True if suspicious
     */
    private function mdlogin_is_suspicious_user_agent($user_agent) {
        $suspicious_patterns = array(
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
            'java', 'perl', 'ruby', 'php', 'go-http', 'libwww', 'lwp'
        );
        
        $user_agent_lower = strtolower($user_agent);
        
        foreach ($suspicious_patterns as $pattern) {
            if (strpos($user_agent_lower, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if user agent is from a known browser
     *
     * @param string $user_agent User agent string
     * @return bool True if known browser
     */
    private function mdlogin_is_known_browser($user_agent) {
        $known_browsers = array(
            'chrome', 'firefox', 'safari', 'edge', 'opera', 'brave'
        );
        
        $user_agent_lower = strtolower($user_agent);
        
        foreach ($known_browsers as $browser) {
            if (strpos($user_agent_lower, $browser) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if user agent is from a mobile device
     *
     * @param string $user_agent User agent string
     * @return bool True if mobile device
     */
    private function mdlogin_is_mobile_device($user_agent) {
        $mobile_indicators = array(
            'mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry',
            'windows phone', 'palm', 'pocket'
        );
        
        $user_agent_lower = strtolower($user_agent);
        
        foreach ($mobile_indicators as $indicator) {
            if (strpos($user_agent_lower, $indicator) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Ensure master database connection for WP Engine
     */
    private function mdlogin_ensure_master_connection() {
        global $wpdb;
        
        // For WP Engine, try to force master database connection
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }

        if ( defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false ) {    
            // Try to reconnect to ensure we're using the master
            if (isset($wpdb->dbh) && $wpdb->dbh) {
                // Force a fresh connection
                $wpdb->close();
                $wpdb->db_connect();
                

            }
        }
    }
} 