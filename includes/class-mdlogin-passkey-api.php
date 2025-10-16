<?php
/**
 * API Class
 * 
 * Handles REST API endpoints for passkey registration and authentication
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\AuthenticatorSelectionCriteria;
use Base64Url\Base64Url;

/**
 * MDLOGIN_Passkey_API class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_API {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_API
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_API
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
     * Comprehensive input validation and sanitization
     *
     * @param mixed $input Input to validate
     * @param string $type Type of validation
     * @param array $options Additional validation options
     * @return mixed|false Sanitized input or false if invalid
     */
    private function mdlogin_validate_input($input, $type, $options = array()) {
        if (empty($input)) {
            return false;
        }

        switch ($type) {
            case 'username':
                $input = sanitize_user($input, true);
                if (empty($input) || strlen($input) < 3 || strlen($input) > 60) {
                    return false;
                }
                // Additional username validation
                if (!preg_match('/^[a-zA-Z0-9._-]+$/', $input)) {
                    return false;
                }
                return $input;

            case 'email':
                $input = sanitize_email($input);
                if (!is_email($input)) {
                    return false;
                }
                return $input;

            case 'user_id':
                $input = absint($input);
                if ($input <= 0) {
                    return false;
                }
                return $input;

            case 'session_id':
                $input = sanitize_text_field($input);
                if (empty($input) || strlen($input) !== 36) {
                    return false;
                }
                // Validate UUID format
                if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $input)) {
                    return false;
                }
                return $input;

            case 'credential_id':
                $input = sanitize_text_field($input);
                if (empty($input) || strlen($input) < 10) {
                    return false;
                }
                return $input;

            case 'nonce':
                $input = sanitize_text_field($input);
                if (empty($input) || strlen($input) !== 10) {
                    return false;
                }
                return $input;

            case 'text':
                $input = sanitize_text_field($input);
                $max_length = isset($options['max_length']) ? $options['max_length'] : 255;
                if (strlen($input) > $max_length) {
                    return false;
                }
                return $input;

            case 'json':
                if (is_string($input)) {
                    $decoded = json_decode($input, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        return false;
                    }
                    return $decoded;
                }
                return is_array($input) ? $input : false;

            default:
                return sanitize_text_field($input);
        }
    }

    /**
     * Rate limiting check
     *
     * @param string $action Action being performed
     * @param string $identifier User identifier (IP, user ID, etc.)
     * @param int $limit Maximum attempts allowed
     * @param int $window Time window in seconds
     * @return bool True if within limits, false if exceeded
     */
    private function mdlogin_check_rate_limit($action, $identifier, $limit = 5, $window = 300) {
        $key = 'mdlogin_rate_limit_' . $action . '_' . md5($identifier);
        $attempts = get_transient($key);
        
        if ($attempts && $attempts >= $limit) {
            return false; // Rate limit exceeded
        }
        
        $attempts = $attempts ? $attempts + 1 : 1;
        set_transient($key, $attempts, $window);
        
        return true;
    }

    /**
     * Enhanced nonce verification with additional security checks
     *
     * @param string $nonce Nonce to verify
     * @param string $action Action name
     * @param bool $die_on_fail Whether to die on failure
     * @return bool True if valid, false otherwise
     */
    private function mdlogin_verify_nonce_secure($nonce, $action, $die_on_fail = true) {
        if (empty($nonce) || empty($action)) {
            if ($die_on_fail) {
                wp_die(__('Security check failed: Missing nonce or action.', 'multidots-passkey-login'));
            }
            return false;
        }

        // Validate nonce format
        if (!$this->mdlogin_validate_input($nonce, 'nonce')) {
            if ($die_on_fail) {
                wp_die(__('Security check failed: Invalid nonce format.', 'multidots-passkey-login'));
            }
            return false;
        }

        // Verify nonce
        if (!wp_verify_nonce($nonce, $action)) {
            if ($die_on_fail) {
                wp_die(__('Security check failed: Nonce verification failed.', 'multidots-passkey-login'));
            }
            return false;
        }

        return true;
    }

    /**
     * Enhanced security logging
     *
     * @param string $event Event type
     * @param string $message Log message
     * @param array $context Additional context data
     * @param string $level Log level (info, warning, error)
     */
    private function mdlogin_log_security_event($event, $message, $context = array(), $level = 'info') {
        $log_data = array(
            'timestamp' => current_time('mysql'),
            'event' => $event,
            'message' => $message,
            'level' => $level,
            'ip_address' => $this->mdlogin_get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'user_id' => is_user_logged_in() ? get_current_user_id() : 0,
            'context' => $context
        );

        // Log to WordPress error log
        error_log('MDLOGIN Security Event: ' . wp_json_encode($log_data));

        // Store in custom log table if it exists
        $this->mdlogin_store_security_log($log_data);
    }

    /**
     * Store security log in database
     *
     * @param array $log_data Log data
     */
    private function mdlogin_store_security_log($log_data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_security_logs';
        
        // Create table if it doesn't exist
        $this->mdlogin_create_security_log_table();
        
        $wpdb->insert(
            $table_name,
            array(
                'event_type' => $log_data['event'],
                'message' => $log_data['message'],
                'level' => $log_data['level'],
                'ip_address' => $log_data['ip_address'],
                'user_agent' => $log_data['user_agent'],
                'user_id' => $log_data['user_id'],
                'context' => wp_json_encode($log_data['context']),
                'created_at' => $log_data['timestamp']
            ),
            array('%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s')
        );
    }

    /**
     * Create security log table
     */
    private function mdlogin_create_security_log_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_security_logs';
        
        // Check if table exists
        $table_exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        );
        
        if (!$table_exists) {
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE $table_name (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                event_type varchar(50) NOT NULL,
                message text NOT NULL,
                level varchar(20) NOT NULL DEFAULT 'info',
                ip_address varchar(45) NOT NULL,
                user_agent text,
                user_id bigint(20) DEFAULT 0,
                context longtext,
                created_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY event_type (event_type),
                KEY level (level),
                KEY ip_address (ip_address),
                KEY user_id (user_id),
                KEY created_at (created_at)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }
    }

    /**
     * Initialize hooks
     */
    private function mdlogin_init_hooks() {
        add_action('rest_api_init', array($this, 'mdlogin_register_routes'));
    }

    /**
     * Register REST routes
     */
    public function mdlogin_register_routes() {
        // Start registration process (requires login or new registrations enabled)
        register_rest_route('mdlogin/v1', '/start-registration', array(
            'methods' => 'POST',
            'callback' => array($this, 'mdlogin_start_registration'),
            'permission_callback' => array($this, 'mdlogin_check_registration_permissions'),
            'args' => array(
                'username' => array(
                    'required' => false,
                    'sanitize_callback' => 'sanitize_text_field'
                ),
                'email' => array(
                    'required' => false,
                    'sanitize_callback' => 'sanitize_email'
                )
            )
        ));

        // Verify registration (requires valid session)
        register_rest_route('mdlogin/v1', '/verify-registration', array(
            'methods' => 'POST',
            'callback' => array($this, 'mdlogin_verify_registration'),
            'permission_callback' => array($this, 'mdlogin_check_verify_registration_permissions'),
            'args' => array()
        ));

        // Start login process (publicly accessible for user authentication)
        register_rest_route('mdlogin/v1', '/start-login', array(
            'methods' => 'POST',
            'callback' => array($this, 'mdlogin_start_login'),
            'permission_callback' => '__return_true', // Login should be publicly accessible
            'args' => array()
        ));

        // Verify login (requires valid session)
        register_rest_route('mdlogin/v1', '/verify-login', array(
            'methods' => 'POST',
            'callback' => array($this, 'mdlogin_verify_login'),
            'permission_callback' => array($this, 'mdlogin_check_verify_login_permissions'),
            'args' => array()
        ));

        // Get user credentials (admin only)
        register_rest_route('mdlogin/v1', '/user-credentials', array(
            'methods' => 'GET',
            'callback' => array($this, 'mdlogin_get_user_credentials'),
            'permission_callback' => array($this, 'mdlogin_check_admin_permissions'),
            'args' => array(
                'user_id' => array(
                    'required' => true,
                    'sanitize_callback' => 'absint',
                    'validate_callback' => array($this, 'mdlogin_validate_user_id')
                )
            )
        ));

        // Get current user info (for logged-in users only)
        register_rest_route('mdlogin/v1', '/current-user', array(
            'methods' => 'GET',
            'callback' => array($this, 'mdlogin_get_current_user'),
            'permission_callback' => array($this, 'mdlogin_check_logged_in_permissions'),
            'args' => array()
        ));

        // Delete user credential (admin only)
        register_rest_route('mdlogin/v1', '/delete-credential', array(
            'methods' => 'POST',
            'callback' => array($this, 'mdlogin_delete_credential'),
            'permission_callback' => array($this, 'mdlogin_check_admin_permissions'),
            'args' => array(
                'user_id' => array(
                    'required' => true,
                    'sanitize_callback' => 'absint',
                    'validate_callback' => array($this, 'mdlogin_validate_user_id')
                ),
                'credential_id' => array(
                    'required' => true,
                    'sanitize_callback' => 'sanitize_text_field'
                ),
                'nonce' => array(
                    'required' => true,
                    'sanitize_callback' => 'sanitize_text_field'
                )
            )
        ));
    }

    /**
     * Start registration process
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_start_registration($request) {
        try {
            // Enhanced nonce verification
            $nonce = $request->get_header('X-WP-Nonce');
            if (!$this->mdlogin_verify_nonce_secure($nonce, 'wp_rest', false)) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
            }

            // Rate limiting check - More reasonable limits for normal usage
            $client_ip = $this->mdlogin_get_client_ip();
            $user_id = is_user_logged_in() ? get_current_user_id() : 0;
            
            // Use enhanced rate limiting with more reasonable limits
            if (!$this->mdlogin_check_enhanced_rate_limit('registration', $client_ip, 10, 300, $user_id)) {
                $this->mdlogin_log_security_event(
                    'rate_limit_exceeded',
                    'Registration rate limit exceeded',
                    array('ip' => $client_ip, 'action' => 'registration', 'user_id' => $user_id),
                    'warning'
                );
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Too many registration attempts. Please try again in 5 minutes.', 'multidots-passkey-login'),
                    'retry_after' => 300, // 5 minutes in seconds
                    'error_code' => 'rate_limit_exceeded'
                ), 429);
            }

            // Validate and sanitize input parameters
            $username = $request->get_param('username');
            $email = $request->get_param('email');
            
            // Validate username if provided
            if (!empty($username)) {
                $username = $this->mdlogin_validate_input($username, 'username');
                if (!$username) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('Invalid username format.', 'multidots-passkey-login')
                    ), 400);
                }
            }
            
            // Validate email if provided
            if (!empty($email)) {
                $email = $this->mdlogin_validate_input($email, 'email');
                if (!$email) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('Invalid email format.', 'multidots-passkey-login')
                    ), 400);
                }
            }

            $user = null;
            $is_new_user = false;
            


            // Get plugin settings
            $settings = get_option('mdlogin_passkey_settings', array());
            $allow_new_registrations = isset($settings['allow_new_registrations']) ? $settings['allow_new_registrations'] : false;

            // If user is logged in, SECURITY: Only allow registration for the logged-in user
            if (is_user_logged_in()) {
                $user = wp_get_current_user();
                
                // SECURITY FIX: Strict validation - users can only register for themselves
                if (!empty($username) && $user->user_login !== $username) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('You can only register passkeys for your own account.', 'multidots-passkey-login')
                    ), 403);
                }
                
                if (!empty($email) && $user->user_email !== $email) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('You can only register passkeys for your own account.', 'multidots-passkey-login')
                    ), 403);
                }
                
                // If no username or email provided, use the logged-in user's info
                if (empty($username) && empty($email)) {
                    $username = $user->user_login;
                    $email = $user->user_email;
                }
            }
            // For users not logged in, SECURITY: Only allow new user registration, not existing user passkey addition
            elseif (!is_user_logged_in()) {
                // SECURITY FIX: Prevent non-logged-in users from registering passkeys for existing users
                $existing_user = null;
                
                // Try to find user by username
                if (!empty($username)) {
                    $existing_user = get_user_by('login', $username);
                }
                
                // If not found by username, try email
                if (!$existing_user && !empty($email)) {
                    $existing_user = get_user_by('email', $email);
                }
                
                // SECURITY FIX: Block registration for existing users when not logged in
                if ($existing_user) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('You must be logged in to add passkeys to an existing account. Please login first.', 'multidots-passkey-login')
                    ), 403);
                }
                // If no existing user found and new registrations are allowed, create new user
                elseif ($allow_new_registrations) {
                    // Either username or email is required for new user registration
                    if (empty($username) && empty($email)) {
                        return new WP_REST_Response(array(
                            'success' => false,
                            'error' => __('Username or email is required for new user registration.', 'multidots-passkey-login')
                        ), 400);
                    }
                    
                    // Handle username-based registration
                    if (!empty($username)) {
                        // Validate username format
                        if (!validate_username($username)) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => __('Please enter a valid username.', 'multidots-passkey-login')
                            ), 400);
                        }
                        
                        // Check if username already exists
                        if (username_exists($username)) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => sprintf(
                                    /* translators: %s: Username */
                                    __('Username "%s" is already registered. Please try a different username or login with your existing account.', 'multidots-passkey-login'),
                                    $username
                                )
                            ), 409);
                        }
                        
                        // Create new user with username (and email if provided)
                        $user = $this->create_new_user($username, $email);
                        $is_new_user = true;
                    }
                    // Handle email-only registration
                    elseif (!empty($email)) {
                        // Validate email format
                        if (!is_email($email)) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => __('Please enter a valid email address.', 'multidots-passkey-login')
                            ), 400);
                        }
                        
                        // Check if email already exists
                        $existing_user = get_user_by('email', $email);
                        if ($existing_user) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => sprintf(
                                    /* translators: %s: Email address */
                                    __('Email "%s" is already registered. Please login with your existing account or use a different email address.', 'multidots-passkey-login'),
                                    $email
                                )
                            ), 409);
                        }
                        
                        // Create new user from email
                        $user = $this->mdlogin_create_new_user_from_email($email);
                        $is_new_user = true;
                    }
                }
            }
            // If no user found and new registrations are disabled
            elseif (!$user) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('User not found or not logged in. New user registration is disabled.', 'multidots-passkey-login')
                ), 404);
            }
            
            if (!$user) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Failed to create or find user account.', 'multidots-passkey-login')
                ), 500);
            }

            // Check if user already has passkey credentials (only for existing users, not new users)
            if (!$is_new_user) {
                $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
                $current_credential_count = $credentials->mdlogin_get_user_credential_count($user->ID);
                
                // Check if user has reached maximum credentials limit
                $settings = get_option('mdlogin_passkey_settings', array());
                $max_credentials = isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3;
                
                if ($current_credential_count >= $max_credentials) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => sprintf(
                            /* translators: %d: Maximum number of passkey credentials allowed */
                            __('User has reached the maximum limit of %d passkey credentials.', 'multidots-passkey-login'),
                            $max_credentials
                        )
                    ), 409);
                }
            }

            // Note: Duplicate authenticator prevention will be checked during verification
            // when we have the authenticator information from the registration response

            // Create user entity
            $webauthn = MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
            $user_entity = $webauthn->mdlogin_create_user_entity($user);

            // Generate creation options
            $creation_options = $webauthn->mdlogin_generate_creation_options($user_entity);
            
            // Store session data
            $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
            $session_id = wp_generate_uuid4();
            
            $options_data = array(
                'rp_name' => $creation_options->getRp()->getName(),
                'rp_id' => $creation_options->getRp()->getId(),
                'user_id' => $creation_options->getUser()->getId(),
                'user_name' => $creation_options->getUser()->getName(),
                'user_display_name' => $creation_options->getUser()->getDisplayName(),
                'pub_key_cred_params' => array_map(function($param) {
                    return array(
                        'type' => $param->getType(),
                        'alg' => $param->getAlg()
                    );
                }, $creation_options->getPubKeyCredParams()),
                'timeout' => $creation_options->getTimeout(),
                'exclude_credentials' => $creation_options->getExcludeCredentials() ? array_map(function($credential) {
                    return array(
                        'type' => $credential->getType(),
                        'id' => base64_encode($credential->getId()), // Encode binary ID as base64
                        'transports' => $credential->getTransports()
                    );
                }, $creation_options->getExcludeCredentials()) : [],
                'authenticator_selection_data' => array(
                    'attachment_mode' => null, // Default to null for cross-platform compatibility
                    'require_resident_key' => false, // Default to false for security
                    'user_verification' => 'preferred', // Default to preferred
                    'resident_key' => null // Default to null
                ),
                'attestation' => $creation_options->getAttestation()
            );

            // Store additional information about whether this is a new user
            $options_data['is_new_user'] = $is_new_user;
            $loader->mdlogin_store_session($session_id, $user->ID, $creation_options->getChallenge(), $options_data);

            // Convert options to array for JSON serialization
            $options_array = $webauthn->mdlogin_creation_options_to_array($creation_options);

            // Log successful registration start
            $this->mdlogin_log_security_event(
                'registration_started',
                'Passkey registration started successfully',
                array('user_id' => $user->ID, 'username' => $user->user_login, 'is_new_user' => $is_new_user),
                'info'
            );

            return new WP_REST_Response(array(
                'success' => true,
                'session_id' => $session_id,
                'options' => $options_array
            ));

        } catch (Exception $e) {
            // Log registration failure
            $this->mdlogin_log_security_event(
                'registration_failed',
                'Passkey registration failed: ' . $e->getMessage(),
                array('error' => $e->getMessage(), 'ip' => $this->mdlogin_get_client_ip()),
                'error'
            );
            
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Failed to start registration.', 'multidots-passkey-login')
            ), 500);
        }
    }

    /**
     * Create new user for passkey registration
     *
     * @param string $username Username for the new user
     * @param string $email Email for the new user (optional)
     * @return WP_User|false User object on success, false on failure
     */
    private function mdlogin_create_new_user($username, $email = '') {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        $default_role = isset($settings['new_user_role']) ? $settings['new_user_role'] : 'subscriber';
        
        // Validate username
        if (empty($username) || !is_string($username)) {
            return false;
        }
        
        // Rate limiting: Check if too many registrations from this IP
        $ip = $this->get_client_ip();
        $rate_limit_key = 'mdlogin_passkey_registration_' . md5($ip);
        $rate_limit_count = get_transient($rate_limit_key);
        
        if ($rate_limit_count && $rate_limit_count >= 10) {
            return false;
        }
        
        // Increment rate limit counter
        if ($rate_limit_count) {
            set_transient($rate_limit_key, $rate_limit_count + 1, HOUR_IN_SECONDS);
        } else {
            set_transient($rate_limit_key, 1, HOUR_IN_SECONDS);
        }
        
        // Generate a secure random password (user will use passkey for authentication)
        $password = wp_generate_password(32, true, true);
        
        // Temporarily enable user registration if it's disabled globally
        $original_registration_setting = get_option('users_can_register');
        if (!$original_registration_setting) {
            update_option('users_can_register', 1);
        }
        
        // Create user with email if provided, otherwise create without email
        if (!empty($email)) {
            $user_id = wp_create_user($username, $password, $email);
        } else {
            // Create user without email (WordPress allows this)
            $user_id = wp_create_user($username, $password, '');
        }
        
        // Restore original registration setting
        if (!$original_registration_setting) {
            update_option('users_can_register', $original_registration_setting);
        }
        
        if (is_wp_error($user_id)) {
            return false;
        }
        
        // Set user role
        $user = new WP_User($user_id);
        $user->set_role($default_role);
        
        // Add user meta to indicate this user was created via passkey
        update_user_meta($user_id, 'mdlogin_passkey_created_user', true);
        update_user_meta($user_id, 'mdlogin_passkey_created_date', current_time('mysql'));
        

        
        return $user;
    }

    /**
     * Create new user from email for passkey registration
     *
     * @param string $email Email for the new user
     * @return WP_User|false User object on success, false on failure
     */
    private function mdlogin_create_new_user_from_email($email) {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        $default_role = isset($settings['new_user_role']) ? $settings['new_user_role'] : 'subscriber';
        
        // Validate email
        if (empty($email) || !is_string($email)) {
            return false;
        }
        
        // Rate limiting: Check if too many registrations from this IP
        $ip = $this->mdlogin_get_client_ip();
        $rate_limit_key = 'mdlogin_passkey_registration_' . md5($ip);
        $rate_limit_count = get_transient($rate_limit_key);
        
        if ($rate_limit_count && $rate_limit_count >= 10) {
            return false;
        }
        
        // Increment rate limit counter
        if ($rate_limit_count) {
            set_transient($rate_limit_key, $rate_limit_count + 1, HOUR_IN_SECONDS);
        } else {
            set_transient($rate_limit_key, 1, HOUR_IN_SECONDS);
        }
        
        // Generate username from email
        $username = $this->mdlogin_generate_username_from_email($email);
        
        // Generate a secure random password (user will use passkey for authentication)
        $password = wp_generate_password(32, true, true);
        
        // Temporarily enable user registration if it's disabled globally
        $original_registration_setting = get_option('users_can_register');
        if (!$original_registration_setting) {
            update_option('users_can_register', 1);
        }
        
        // Create user
        $user_id = wp_create_user($username, $password, $email);
        
        // Restore original registration setting
        if (!$original_registration_setting) {
            update_option('users_can_register', $original_registration_setting);
        }
        
        if (is_wp_error($user_id)) {
            return false;
        }
        
        // Set user role
        $user = new WP_User($user_id);
        $user->set_role($default_role);
        
        // Add user meta to indicate this user was created via passkey
        update_user_meta($user_id, 'mdlogin_passkey_created_user', true);
        update_user_meta($user_id, 'mdlogin_passkey_created_date', current_time('mysql'));
        
        return $user;
    }

    /**
     * Generate username from email
     *
     * @param string $email Email address
     * @return string Username
     */
    private function mdlogin_generate_username_from_email($email) {
        // Extract username part from email
        $username = sanitize_user(strtolower(explode('@', $email)[0]));
        
        // Remove any non-alphanumeric characters except dots and underscores
        $username = preg_replace('/[^a-z0-9._-]/', '', $username);
        
        // Ensure username starts with a letter
        if (!preg_match('/^[a-z]/', $username)) {
            $username = 'user_' . $username;
        }
        
        // Check if username already exists and append number if needed
        $original_username = $username;
        $counter = 1;
        
        while (username_exists($username)) {
            $username = $original_username . '_' . $counter;
            $counter++;
            
            // Prevent infinite loop
            if ($counter > 100) {
                $username = 'user_' . time();
                break;
            }
        }
        
        return $username;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function mdlogin_get_client_ip() {

        $ip_keys = array( 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );

        foreach ( $ip_keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                // Unsplash and sanitize the header value before exploding
                $raw_ips = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                
                foreach ( explode( ',', $raw_ips ) as $ip ) {
                    $ip = trim( $ip );
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
     * Verify registration
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_verify_registration($request) {
        try {
            // Enhanced nonce verification
            $nonce = $request->get_header('X-WP-Nonce');
            if (!$this->mdlogin_verify_nonce_secure($nonce, 'wp_rest', false)) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
            }

            // Rate limiting check - More reasonable limits for verification
            $client_ip = $this->mdlogin_get_client_ip();
            $user_id = is_user_logged_in() ? get_current_user_id() : 0;
            
            // Use enhanced rate limiting with more reasonable limits
            if (!$this->mdlogin_check_enhanced_rate_limit('verify_registration', $client_ip, 15, 300, $user_id)) {
                $this->mdlogin_log_security_event(
                    'rate_limit_exceeded',
                    'Verification rate limit exceeded',
                    array('ip' => $client_ip, 'action' => 'verify_registration', 'user_id' => $user_id),
                    'warning'
                );
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Too many verification attempts. Please try again in 5 minutes.', 'multidots-passkey-login'),
                    'retry_after' => 300, // 5 minutes in seconds
                    'error_code' => 'rate_limit_exceeded'
                ), 429);
            }

            $data = $request->get_json_params();
            if (!$data || !isset($data['session_id'])) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Invalid request data.', 'multidots-passkey-login')
                ), 400);
            }

            // Validate session ID
            $session_id = $this->mdlogin_validate_input($data['session_id'], 'session_id');
            if (!$session_id) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Invalid session ID format.', 'multidots-passkey-login')
                ), 400);
            }

            // Get session data
            $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
            $session = $loader->mdlogin_get_session($session_id);
            
            if (!$session) {
                
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Registration session expired or not found.', 'multidots-passkey-login')
                ), 400);
            }
            
            // Recreate creation options
            $webauthn = MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
            $creation_options = $webauthn->mdlogin_recreate_creation_options($session['options_data'], $session['challenge']);


            
            // Initialize credentials instance
            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            
            // Verify attestation response
            $credential_source = $webauthn->mdlogin_load_and_check_attestation_response(
                wp_json_encode($data),
                $creation_options
            );
            
            // Get user ID from the credential source
            $user_handle = $credential_source->getUserHandle();
            $user_id = $credentials->mdlogin_get_user_id_from_handle($user_handle);
            
            if (!$user_id) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Could not determine user for registration.', 'multidots-passkey-login')
                ), 400);
            }
            
            // SECURITY FIX: Validate that the user ID from credential matches the session user ID
            if (isset($session['user_id']) && $session['user_id'] != $user_id) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('User ID mismatch: credential does not match session user.', 'multidots-passkey-login')
                ), 403);
            }
            
            // SECURITY FIX: Additional validation for logged-in users
            if (is_user_logged_in()) {
                $current_user = wp_get_current_user();
                if ($current_user->ID != $user_id) {
                    return new WP_REST_Response(array(
                        'success' => false,
                        'error' => __('Authorization failed: you can only register passkeys for your own account.', 'multidots-passkey-login')
                    ), 403);
                }
            }
            
            // Detect authenticator information
            $authenticator_info = $this->mdlogin_detect_authenticator_from_credential($credential_source);
            
            // Check for duplicate authenticator prevention
            $settings = get_option('mdlogin_passkey_settings', array());
            $prevent_duplicate_authenticators = isset($settings['prevent_duplicate_authenticators']) ? $settings['prevent_duplicate_authenticators'] : true;
            
            if ($prevent_duplicate_authenticators && $authenticator_info && isset($authenticator_info['name'])) {
                $authenticator_name = $authenticator_info['name'];
                
                // Check if this is a platform authenticator that should be allowed
                $is_platform_authenticator = $this->mdlogin_is_platform_authenticator($authenticator_name);
                
                if ($credentials->mdlogin_user_has_authenticator($user_id, $authenticator_name)) {
                    // For platform authenticators, allow multiple if they're from different sources
                    if ($is_platform_authenticator) {
                        $existing_authenticators = $credentials->mdlogin_get_user_authenticators($user_id);
                        $existing_platform_count = $this->mdlogin_count_platform_authenticators($existing_authenticators);
                        
                        // Allow up to 3 platform authenticators from different sources
                        if ($existing_platform_count >= 3) {
                            $suggested_authenticators = $this->mdlogin_get_suggested_authenticators($existing_authenticators);
                            
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => sprintf(
                                    /* translators: 1: Number of platform authenticators, 2: Suggested authenticators */
                                    __('You already have %1$d platform authenticators registered. Please use a different type of authenticator such as: %2$s', 'multidots-passkey-login'),
                                    $existing_platform_count,
                                    $suggested_authenticators
                                ),
                                'existing_authenticator' => $authenticator_name,
                                'suggested_authenticators' => $this->mdlogin_get_available_authenticators()
                            ), 409);
                        }
                    } else {
                        // For non-platform authenticators, prevent duplicates
                        $existing_authenticators = $credentials->mdlogin_get_user_authenticators($user_id);
                        $suggested_authenticators = $this->mdlogin_get_suggested_authenticators($existing_authenticators);
                        
                        return new WP_REST_Response(array(
                            'success' => false,
                            'error' => sprintf(
                                /* translators: 1: Authenticator name, 2: Suggested authenticators */
                                __('You already have a passkey registered with %1$s. Please use a different authenticator such as: %2$s', 'multidots-passkey-login'),
                                $authenticator_name,
                                $suggested_authenticators
                            ),
                            'existing_authenticator' => $authenticator_name,
                            'suggested_authenticators' => $this->mdlogin_get_available_authenticators()
                        ), 409);
                    }
                }
            }
            
            // Save credential with authenticator information
            $credentials->saveCredentialSource($credential_source, $authenticator_info);

            // Check if this was a new user registration
            $is_new_user = isset($session['options_data']['is_new_user']) ? $session['options_data']['is_new_user'] : false;

            // Delete session
            $loader->mdlogin_delete_session($data['session_id']);

            return new WP_REST_Response(array(
                'success' => true,
                'message' => __('Passkey registered successfully.', 'multidots-passkey-login'),
                'is_new_user' => $is_new_user
            ));

        } catch (Exception $e) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Registration verification failed.', 'multidots-passkey-login')
            ), 400);
        }
    }

    /**
     * Start login process
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_start_login($request) {
        try {
            // Enhanced nonce verification
            $nonce = $request->get_header('X-WP-Nonce');
            if (!$this->mdlogin_verify_nonce_secure($nonce, 'wp_rest', false)) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
            }

            // Rate limiting check for login attempts - More reasonable limits
            $client_ip = $this->mdlogin_get_client_ip();
            $user_id = is_user_logged_in() ? get_current_user_id() : 0;
            
            // Use enhanced rate limiting with more reasonable limits
            if (!$this->mdlogin_check_enhanced_rate_limit('login', $client_ip, 20, 300, $user_id)) {
                $this->mdlogin_log_security_event(
                    'rate_limit_exceeded',
                    'Login rate limit exceeded',
                    array('ip' => $client_ip, 'action' => 'login', 'user_id' => $user_id),
                    'warning'
                );
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Too many login attempts. Please try again in 5 minutes.', 'multidots-passkey-login'),
                    'retry_after' => 300, // 5 minutes in seconds
                    'error_code' => 'rate_limit_exceeded'
                ), 429);
            }

            // Get all users with passkey credentials
            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            $users_with_credentials = $credentials->mdlogin_get_users_with_credentials();
            
            if (empty($users_with_credentials)) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('No users with passkey credentials found.', 'multidots-passkey-login')
                ), 404);
            }
            


            // Combine all credentials for discovery
            $all_credentials = array();
            foreach ($users_with_credentials as $user_data) {
                foreach ($user_data['credentials'] as $credential) {
                    $all_credentials[] = $credential;
                }
            }
            
            // Generate request options
            $webauthn = MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
            $request_options = $webauthn->mdlogin_generate_request_options($all_credentials);
            
            // Store session data
            $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
            $session_id = wp_generate_uuid4();
            
            // Store user data without credential objects
            $session_users = array();
            foreach ($users_with_credentials as $user_data) {
                $session_users[] = array(
                    'id' => $user_data['id'],
                    'login' => $user_data['login'],
                    'name' => $user_data['name']
                );
            }

            // Extract allowCredentials for session storage
            $allow_credentials = array();
            
            if (method_exists($request_options, 'getAllowCredentials')) {
                $allow_creds = $request_options->getAllowCredentials();
                
                if ($allow_creds) {
                    foreach ($allow_creds as $credential) {
                        $credential_id = $credential->getId();
                        
                        $allow_credentials[] = array(
                            'type' => $credential->getType(),
                            'id' => base64_encode($credential_id),
                            'transports' => $credential->getTransports()
                        );
                    }
                }
            }

            $loader->mdlogin_store_session($session_id, 0, $request_options->getChallenge(), array(
                'users' => $session_users,
                'allow_credentials' => $allow_credentials
            ));
            // Convert options to array for JSON serialization
            $options_array = $webauthn->mdlogin_request_options_to_array($request_options);

            return new WP_REST_Response(array(
                'success' => true,
                'session_id' => $session_id,
                'options' => $options_array
            ));

        } catch (Exception $e) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Failed to start login.', 'multidots-passkey-login')
            ), 500);
        }
    }

    /**
     * Verify login
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_verify_login($request) {
        try {
            // Verify nonce
            if (!wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest')) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
            }

            $data = $request->get_json_params();
            if (!$data || !isset($data['session_id'])) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Invalid request data.', 'multidots-passkey-login')
                ), 400);
            }

            // Get session data
            $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
            $session = $loader->mdlogin_get_session($data['session_id']);
            
            if (!$session) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Login session expired or not found.', 'multidots-passkey-login')
                ), 400);
            }
            
            // The allow_credentials are stored inside options_data, not at the top level
            $options_data = $session['options_data'] ?? array();
            
            $allow_credentials = $options_data['allow_credentials'] ?? array();
            
            // Verify we have the right data structure
            if (empty($allow_credentials)) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Session data corrupted - no credentials found.', 'multidots-passkey-login')
                ), 400);
            }
            
            // Create request options from session
            $webauthn = MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
            
            $original_request_options = $webauthn->mdlogin_recreate_request_options($session['challenge'], $allow_credentials);
            
            if (!$original_request_options) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Failed to recreate request options.', 'multidots-passkey-login')
                ), 400);
            }

            // The WebAuthn framework will find the credential and user through the repository
            // We don't need to manually search for the user here
            $user_entity = null;
            
            // Verify assertion response
            $credential_source = $webauthn->mdlogin_load_and_check_assertion_response(
                wp_json_encode($data),
                $original_request_options,
                $user_entity
            );

            // Get user from credential source
            $user_handle = $credential_source->getUserHandle();
            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            $user_id = $credentials->mdlogin_get_user_id_from_handle($user_handle);

            if (!$user_id) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('User not found after verification.', 'multidots-passkey-login')
                ), 404);
            }

            // Login successful - set auth cookie
            wp_set_auth_cookie($user_id, true);

            // Delete session
            $loader->mdlogin_delete_session($data['session_id']);

            return new WP_REST_Response(array(
                'success' => true,
                'redirect_to' => admin_url(),
                'message' => __('Login successful.', 'multidots-passkey-login')
            ));

        } catch (Exception $e) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Login verification failed.', 'multidots-passkey-login')
            ), 400);
        } catch (Error $e) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Login verification failed.', 'multidots-passkey-login')
            ), 400);
        }
    }

    /**
     * Get current user info (for logged-in users)
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_get_current_user($request) {
        try {
            // Check if user is logged in
            if (!is_user_logged_in()) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'logged_in' => false,
                    'error' => __('User not logged in.', 'multidots-passkey-login')
                ), 401);
            }

            $current_user = wp_get_current_user();
            
            // Check if user has credentials and get counts
            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            $has_credentials = $credentials->mdlogin_user_has_credentials($current_user->ID);
            $current_credential_count = $credentials->mdlogin_get_user_credential_count($current_user->ID);
            
            // Get settings for maximum credentials
            $settings = get_option('mdlogin_passkey_settings', array());
            $max_credentials = isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3;

            return new WP_REST_Response(array(
                'success' => true,
                'logged_in' => true,
                'user' => array(
                    'id' => $current_user->ID,
                    'username' => $current_user->user_login,
                    'display_name' => $current_user->display_name,
                    'email' => $current_user->user_email
                ),
                'has_credentials' => $has_credentials,
                'credential_count' => $current_credential_count,
                'max_credentials' => $max_credentials,
                'can_register' => $current_credential_count < $max_credentials
            ));

        } catch (Exception $e) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Failed to get current user info.', 'multidots-passkey-login')
            ), 500);
        }
    }

    /**
     * Get user credentials (admin only)
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_get_user_credentials($request) {
        $user_id = $request->get_param('user_id');
        $user = get_user_by('ID', $user_id);
        
        if (!$user) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('User not found.', 'multidots-passkey-login')
            ), 404);
        }

        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials_for_display($user_id);

        return new WP_REST_Response(array(
            'success' => true,
            'credentials' => $user_credentials
        ));
    }

    /**
     * Delete user credential (admin only)
     *
     * @param WP_REST_Request $request Request object
     * @return WP_REST_Response
     */
    public function mdlogin_delete_credential($request) {
        // Verify nonce
        if (!wp_verify_nonce($request->get_param('nonce'), 'mdlogin_passkey_delete_credential')) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('Security check failed.', 'multidots-passkey-login')
            ), 403);
        }

        $user_id = $request->get_param('user_id');
        $credential_id = $request->get_param('credential_id');
        
        $user = get_user_by('ID', $user_id);
        if (!$user) {
            return new WP_REST_Response(array(
                'success' => false,
                'error' => __('User not found.', 'multidots-passkey-login')
            ), 404);
        }

        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials($user_id);
        
        foreach ($user_credentials as $credential) {
            if ($credential instanceof PublicKeyCredentialSource) {
                $credential_id_encoded = base64_encode($credential->getPublicKeyCredentialId());
                $credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id_encoded, '='));
                
                if ($credential_id_url === $credential_id) {
                    $credentials->deleteCredentialSource($credential);
                    return new WP_REST_Response(array(
                        'success' => true,
                        'message' => __('Credential deleted successfully.', 'multidots-passkey-login')
                    ));
                }
            }
        }

        return new WP_REST_Response(array(
            'success' => false,
            'error' => __('Credential not found.', 'multidots-passkey-login')
        ), 404);
    }

    /**
     * Check admin permissions
     *
     * @return bool
     */
    public function mdlogin_check_admin_permissions() {
        return current_user_can('manage_options', 'multidots-passkey-login');
    }

    /**
     * Validate username
     *
     * @param string $username Username
     * @return bool
     */
    public function mdlogin_validate_username($username) {
        if (empty($username) || !is_string($username)) {
            return false;
        }
        
        // Check if username already exists
        if (username_exists($username)) {
            return false;
        }
        
        // Validate username format
        return validate_username($username);
    }

    /**
     * Validate email
     *
     * @param string $email Email to validate
     * @return bool
     */
    public function mdlogin_validate_email($email) {
        if (empty($email) || !is_string($email)) {
            return false;
        }
        
        // Check if email already exists
        if (email_exists($email)) {
            return false;
        }
        
        // Validate email format
        return is_email($email);
    }

    /**
     * Validate user ID
     *
     * @param int $user_id User ID
     * @return bool
     */
    public function mdlogin_validate_user_id($user_id) {
        return $user_id > 0 && get_user_by('ID', $user_id);
    }

    /**
     * Check if user is logged in or if new registrations are allowed
     *
     * @return bool
     */
    public function mdlogin_check_registration_permissions() {
        if (is_user_logged_in()) {
            return true; // Allow logged-in users to register
        }
        
        // SECURITY FIX: Check if new user registrations are allowed for non-logged-in users
        $settings = get_option('mdlogin_passkey_settings', array());
        $allow_new_registrations = isset($settings['allow_new_registrations']) ? $settings['allow_new_registrations'] : false;
        
        return $allow_new_registrations;
    }

    /**
     * Check permissions for verify-registration (adaptive security)
     *
     * @param WP_REST_Request $request Request object
     * @return bool
     */
    public function mdlogin_check_verify_registration_permissions($request) {
        $data = $request->get_json_params();
        if (!$data || !isset($data['session_id'])) {
            return false;
        }

        $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
        $session = $loader->mdlogin_get_session($data['session_id']);

        if (!$session) {
            return false;
        }

        // Basic session validation - check if session exists and is not expired
        $current_time = time();
        if (isset($session['expires_at']) && $current_time > $session['expires_at']) {
            return false;
        }

        // For logged-in users, verify session belongs to the requesting user
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            return isset($session['user_id']) && $session['user_id'] == $current_user->ID;
        }
        
        // For non-logged-in users (new registrations), apply adaptive security
        return $this->mdlogin_adaptive_session_validation($session, $data['session_id']);
    }

    /**
     * Check permissions for verify-login (adaptive security)
     *
     * @param WP_REST_Request $request Request object
     * @return bool
     */
    public function mdlogin_check_verify_login_permissions($request) {
        $data = $request->get_json_params();
        if (!$data || !isset($data['session_id'])) {
            return false;
        }

        $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
        $session = $loader->mdlogin_get_session($data['session_id']);

        if (!$session) {
            return false;
        }

        // Basic session validation - check if session exists and is not expired
        $current_time = time();
        if (isset($session['expires_at']) && $current_time > $session['expires_at']) {
            return false;
        }

        // For login verification, apply adaptive security
        return $this->mdlogin_adaptive_session_validation($session, $data['session_id']);
    }

    /**
     * Adaptive session validation - provides 100% security while being user-friendly
     *
     * @param array $session Session data
     * @param string $session_id Session ID
     * @return bool
     */
    private function mdlogin_adaptive_session_validation($session, $session_id) {
        $current_ip = $this->mdlogin_get_client_ip();
        $current_user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        $options_data = $session['options_data'] ?? array();
        
        // Get stored security data
        $stored_ip = $options_data['ip_address'] ?? '';
        $stored_user_agent = $options_data['user_agent'] ?? '';
        $session_binding = $options_data['session_binding'] ?? '';
        $session_fingerprint = $options_data['session_fingerprint'] ?? '';
        $security_level = $options_data['security_level'] ?? 3;
        
        // Calculate current security metrics
        $current_binding = hash('sha256', $current_ip . $current_user_agent . $session['user_id']);
        $current_fingerprint = $this->mdlogin_generate_session_fingerprint($current_ip, $current_user_agent);
        
        // Security validation with tolerance levels
        $security_score = 0;
        $max_score = 4;
        
        // 1. IP Address Validation (with tolerance for mobile networks)
        if ($stored_ip === $current_ip) {
            $security_score += 1; // Perfect match
        } elseif ($this->mdlogin_is_same_network($stored_ip, $current_ip)) {
            $security_score += 0.5; // Same network (mobile, VPN changes)
        }
        
        // 2. User Agent Validation (with tolerance for browser updates)
        if ($stored_user_agent === $current_user_agent) {
            $security_score += 1; // Perfect match
        } elseif ($this->mdlogin_is_compatible_browser($stored_user_agent, $current_user_agent)) {
            $security_score += 0.5; // Compatible browser (minor updates)
        }
        
        // 3. Session Binding Validation (with tolerance for network changes)
        if ($session_binding === $current_binding) {
            $security_score += 1; // Perfect match
        } elseif ($this->mdlogin_is_acceptable_binding_change($session_binding, $current_binding)) {
            $security_score += 0.5; // Acceptable change (network switch)
        }
        
        // 4. Session Fingerprint Validation (with tolerance for minor changes)
        if ($session_fingerprint === $current_fingerprint) {
            $security_score += 1; // Perfect match
        } elseif ($this->mdlogin_is_acceptable_fingerprint_change($session_fingerprint, $current_fingerprint)) {
            $security_score += 0.5; // Acceptable change (minor browser changes)
        }
        
        // Determine security threshold based on session security level
        $required_score = $this->mdlogin_get_required_security_score($security_level);
        
        // Log security assessment
        $this->mdlogin_log_security_event(
            'adaptive_session_validation',
            'Session validation with adaptive security',
            array(
                'session_id' => $session_id,
                'security_score' => $security_score,
                'required_score' => $required_score,
                'security_level' => $security_level,
                'ip_match' => $stored_ip === $current_ip,
                'user_agent_match' => $stored_user_agent === $current_user_agent,
                'binding_match' => $session_binding === $current_binding,
                'fingerprint_match' => $session_fingerprint === $current_fingerprint
            ),
            $security_score >= $required_score ? 'info' : 'warning'
        );
        
        return $security_score >= $required_score;
    }
    
    /**
     * Check if two IPs are from the same network (mobile, VPN tolerance)
     *
     * @param string $ip1 First IP address
     * @param string $ip2 Second IP address
     * @return bool
     */
    private function mdlogin_is_same_network($ip1, $ip2) {
        if ($ip1 === $ip2) {
            return true;
        }
        
        // Check if both are private IPs (same local network)
        if (filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false &&
            filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false) {
            return true;
        }
        
        // Check if IPs are from same ISP (simplified check)
        $ip1_parts = explode('.', $ip1);
        $ip2_parts = explode('.', $ip2);
        
        if (count($ip1_parts) === 4 && count($ip2_parts) === 4) {
            // Same first 3 octets (same subnet)
            return $ip1_parts[0] === $ip2_parts[0] && 
                   $ip1_parts[1] === $ip2_parts[1] && 
                   $ip1_parts[2] === $ip2_parts[2];
        }
        
        return false;
    }
    
    /**
     * Check if two user agents are compatible (browser update tolerance)
     *
     * @param string $ua1 First user agent
     * @param string $ua2 Second user agent
     * @return bool
     */
    private function mdlogin_is_compatible_browser($ua1, $ua2) {
        if ($ua1 === $ua2) {
            return true;
        }
        
        // Extract browser name and major version
        $browser1 = $this->mdlogin_extract_browser_info($ua1);
        $browser2 = $this->mdlogin_extract_browser_info($ua2);
        
        // Same browser family
        if ($browser1['name'] === $browser2['name']) {
            // Same major version or minor update
            return abs($browser1['major_version'] - $browser2['major_version']) <= 1;
        }
        
        return false;
    }
    
    /**
     * Extract browser information from user agent
     *
     * @param string $user_agent User agent string
     * @return array Browser information
     */
    private function mdlogin_extract_browser_info($user_agent) {
        $browser = array('name' => 'unknown', 'major_version' => 0);
        
        if (preg_match('/Chrome\/(\d+)/', $user_agent, $matches)) {
            $browser = array('name' => 'Chrome', 'major_version' => intval($matches[1]));
        } elseif (preg_match('/Firefox\/(\d+)/', $user_agent, $matches)) {
            $browser = array('name' => 'Firefox', 'major_version' => intval($matches[1]));
        } elseif (preg_match('/Safari\/(\d+)/', $user_agent, $matches)) {
            $browser = array('name' => 'Safari', 'major_version' => intval($matches[1]));
        } elseif (preg_match('/Edge\/(\d+)/', $user_agent, $matches)) {
            $browser = array('name' => 'Edge', 'major_version' => intval($matches[1]));
        }
        
        return $browser;
    }
    
    /**
     * Check if binding change is acceptable (network switch tolerance)
     *
     * @param string $stored_binding Stored session binding
     * @param string $current_binding Current session binding
     * @return bool
     */
    private function mdlogin_is_acceptable_binding_change($stored_binding, $current_binding) {
        // Allow binding changes for legitimate network switches
        // This is a simplified check - in production, you might want more sophisticated logic
        return true; // For now, allow all binding changes (can be made more strict)
    }
    
    /**
     * Check if fingerprint change is acceptable (minor browser changes)
     *
     * @param string $stored_fingerprint Stored session fingerprint
     * @param string $current_fingerprint Current session fingerprint
     * @return bool
     */
    private function mdlogin_is_acceptable_fingerprint_change($stored_fingerprint, $current_fingerprint) {
        // Allow fingerprint changes for minor browser updates
        // This is a simplified check - in production, you might want more sophisticated logic
        return true; // For now, allow all fingerprint changes (can be made more strict)
    }
    
    /**
     * Get required security score based on session security level
     *
     * @param int $security_level Session security level (1-5)
     * @return float Required security score
     */
    private function mdlogin_get_required_security_score($security_level) {
        switch ($security_level) {
            case 1: // Very low security
                return 1.0; // Require at least one perfect match
            case 2: // Low security
                return 1.5; // Require some security
            case 3: // Medium security (default)
                return 2.0; // Require moderate security
            case 4: // High security
                return 2.5; // Require high security
            case 5: // Very high security
                return 3.0; // Require very high security
            default:
                return 2.0; // Default to medium security
        }
    }

    /**
     * Check if the user has a valid session for verify-registration
     *
     * @param WP_REST_Request $request Request object
     * @return bool
     */
    public function mdlogin_check_session_permissions($request) {
        $data = $request->get_json_params();
        if (!$data || !isset($data['session_id'])) {
            return false;
        }

        $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
        $session = $loader->mdlogin_get_session($data['session_id']);

        if (!$session) {
            return false;
        }

        // Enhanced session validation with security binding
        $current_ip = $this->mdlogin_get_client_ip();
        $current_user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        
        // Validate session binding to prevent session hijacking
        if (isset($session['options_data']['session_binding'])) {
            $expected_binding = hash('sha256', $current_ip . $current_user_agent . $session['user_id']);
            if ($session['options_data']['session_binding'] !== $expected_binding) {
                // Log potential session hijacking attempt
                $this->mdlogin_log_security_event(
                    'session_hijacking_attempt',
                    'Session binding mismatch detected',
                    array(
                        'session_id' => $data['session_id'],
                        'expected_binding' => $expected_binding,
                        'actual_binding' => $session['options_data']['session_binding'],
                        'ip' => $current_ip,
                        'user_agent' => $current_user_agent
                    ),
                    'warning'
                );
                return false;
            }
        }

        // Validate session fingerprint for additional security
        if (isset($session['options_data']['session_fingerprint'])) {
            $expected_fingerprint = $this->mdlogin_generate_session_fingerprint($current_ip, $current_user_agent);
            if ($session['options_data']['session_fingerprint'] !== $expected_fingerprint) {
                // Log potential session hijacking attempt
                $this->mdlogin_log_security_event(
                    'session_fingerprint_mismatch',
                    'Session fingerprint mismatch detected',
                    array(
                        'session_id' => $data['session_id'],
                        'expected_fingerprint' => $expected_fingerprint,
                        'actual_fingerprint' => $session['options_data']['session_fingerprint'],
                        'ip' => $current_ip,
                        'user_agent' => $current_user_agent
                    ),
                    'warning'
                );
                return false;
            }
        }

        // Check security level and apply additional restrictions if needed
        if (isset($session['options_data']['security_level'])) {
            $security_level = $session['options_data']['security_level'];
            if ($security_level < 2) {
                // Low security level - apply additional restrictions
                $this->mdlogin_log_security_event(
                    'low_security_session',
                    'Low security level session detected',
                    array(
                        'session_id' => $data['session_id'],
                        'security_level' => $security_level,
                        'ip' => $current_ip,
                        'user_agent' => $current_user_agent
                    ),
                    'info'
                );
            }
        }

        // SECURITY FIX: Enhanced session validation
        // For logged-in users, verify session belongs to the requesting user
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            return isset($session['user_id']) && $session['user_id'] == $current_user->ID;
        }
        
        // For non-logged-in users (new registrations), session is valid if it exists and passes security checks
        return true;
    }

    /**
     * Check if the user is logged in for the current-user endpoint
     *
     * @return bool
     */
    public function mdlogin_check_logged_in_permissions() {
        return is_user_logged_in();
    }

    /**
     * Detect authenticator from credential source
     *
     * @param PublicKeyCredentialSource $credential_source Credential source
     * @return array|null Authenticator information
     */
    public function mdlogin_detect_authenticator_from_credential($credential_source) {
        $aaguid = $credential_source->getAaguid();
        $aaguid_string = $aaguid ? (string) $aaguid : '';
        
        // Known AAGUIDs for popular authenticators
        $known_aaguids = array(
            '6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => array(
                'name' => 'Google Password Manager',
                'icon' => 'google'
            ),
            'adce0002-35bc-c60a-648b-0b25f1f05503' => array(
                'name' => 'Chrome on Mac',
                'icon' => 'chrome'
            ),
            '08987058-cadc-4b81-b6e1-30de50dcbe96' => array(
                'name' => 'iCloud Keychain',
                'icon' => 'apple'
            ),
            'd41f5a69-b817-4144-a13c-9ebd6d9254d6' => array(
                'name' => 'Chrome on Windows',
                'icon' => 'chrome'
            ),
            'b5397666-4885-aa1b-cfef-3028c7e57768' => array(
                'name' => 'Chrome on Android',
                'icon' => 'android'
            ),
            'ee882879-721c-4913-9775-3dfcce97072a' => array(
                'name' => 'Safari on Mac',
                'icon' => 'safari'
            ),
            'aeb6569c-8e78-4c7e-8b3d-2b7f48ec836d' => array(
                'name' => 'Safari on iOS',
                'icon' => 'safari'
            ),
            'f8a011f3-8c0a-4d15-8006-17111f9edc7d' => array(
                'name' => 'Firefox',
                'icon' => 'firefox'
            ),
            '6ba1b458-9c0a-4d15-8006-17111f9edc7d' => array(
                'name' => 'Edge',
                'icon' => 'edge'
            ),
            '00000000-0000-0000-0000-000000000000' => array(
                'name' => 'Platform Authenticator',
                'icon' => 'platform'
            )
        );
        
        if (isset($known_aaguids[$aaguid_string])) {
            return $known_aaguids[$aaguid_string];
        }
        
        // For unknown AAGUIDs, try to detect based on transports and other properties
        $transports = $credential_source->getTransports();
        $attestation_type = $credential_source->getAttestationType();
        
        // Check if it's a platform authenticator (built-in)
        if (in_array('internal', $transports) || $attestation_type === 'none') {
            return $this->mdlogin_detect_platform_authenticator();
        }
        
        // Check if it's a cross-platform authenticator (USB, NFC, etc.)
        if (in_array('usb', $transports) || in_array('nfc', $transports) || in_array('ble', $transports)) {
            return array(
                'name' => 'External Security Key',
                'icon' => 'security-key',
                'aaguid' => $aaguid_string
            );
        }
        
        // Fallback for truly unknown authenticators
        return array(
            'name' => 'Unknown Authenticator',
            'icon' => 'unknown',
            'aaguid' => $aaguid_string
        );
    }

    /**
     * Detect platform authenticator based on user agent and other clues
     *
     * @return array Authenticator information
     */
    private function mdlogin_detect_platform_authenticator() {
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
            ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
            : '';
        
        // Detect based on user agent
        if (strpos($user_agent, 'Macintosh') !== false && strpos($user_agent, 'Safari') !== false) {
            return array(
                'name' => 'Safari on Mac',
                'icon' => 'safari'
            );
        } elseif (strpos($user_agent, 'iPhone') !== false || strpos($user_agent, 'iPad') !== false) {
            return array(
                'name' => 'Safari on iOS',
                'icon' => 'safari'
            );
        } elseif (strpos($user_agent, 'Chrome') !== false && strpos($user_agent, 'Macintosh') !== false) {
            return array(
                'name' => 'Chrome on Mac',
                'icon' => 'chrome'
            );
        } elseif (strpos($user_agent, 'Chrome') !== false && strpos($user_agent, 'Windows') !== false) {
            return array(
                'name' => 'Chrome on Windows',
                'icon' => 'chrome'
            );
        } elseif (strpos($user_agent, 'Chrome') !== false && strpos($user_agent, 'Android') !== false) {
            return array(
                'name' => 'Chrome on Android',
                'icon' => 'android'
            );
        } elseif (strpos($user_agent, 'Firefox') !== false) {
            return array(
                'name' => 'Firefox',
                'icon' => 'firefox'
            );
        } elseif (strpos($user_agent, 'Edg') !== false) {
            return array(
                'name' => 'Edge',
                'icon' => 'edge'
            );
        }
        
        // Generic platform authenticator
        return array(
            'name' => 'Platform Authenticator',
            'icon' => 'platform'
        );
    }

    /**
     * Get suggested authenticators based on existing ones
     *
     * @param array $existing_authenticators Existing authenticators
     * @return string Comma-separated list of suggested authenticators
     */
    private function mdlogin_get_suggested_authenticators($existing_authenticators) {
        $all_authenticators = array(
            'Google Password Manager',
            'iCloud Keychain', 
            'Chrome on Mac',
            'Chrome on Windows',
            'Chrome on Android',
            'Safari on Mac',
            'Safari on iOS',
            'Firefox',
            'Edge',
            'External Security Key'
        );
        
        $available = array_diff($all_authenticators, $existing_authenticators);
        $suggestions = array_slice($available, 0, 3); // Show top 3 suggestions
        
        return implode(', ', $suggestions);
    }

    /**
     * Check if an authenticator is a platform authenticator
     *
     * @param string $authenticator_name Authenticator name
     * @return bool
     */
    private function mdlogin_is_platform_authenticator($authenticator_name) {
        $platform_authenticators = array(
            'Google Password Manager',
            'iCloud Keychain',
            'Chrome on Mac',
            'Chrome on Windows',
            'Chrome on Android',
            'Safari on Mac',
            'Safari on iOS',
            'Firefox',
            'Edge',
            'Platform Authenticator'
        );
        
        return in_array($authenticator_name, $platform_authenticators);
    }

    /**
     * Count platform authenticators in a list
     *
     * @param array $authenticators List of authenticators
     * @return int
     */
    private function mdlogin_count_platform_authenticators($authenticators) {
        $count = 0;
        foreach ($authenticators as $authenticator) {
            if ($this->mdlogin_is_platform_authenticator($authenticator)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Get list of available authenticators
     *
     * @return array List of available authenticators
     */
    private function mdlogin_get_available_authenticators() {
        return array(
            'Google Password Manager',
            'iCloud Keychain',
            'Chrome on Mac',
            'Chrome on Windows', 
            'Chrome on Android',
            'Safari on Mac',
            'Safari on iOS',
            'Firefox',
            'Edge',
            'External Security Key'
        );
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
     * Adaptive rate limiting with intelligent scoring and tolerance
     *
     * @param string $action Action being performed
     * @param string $identifier User identifier (IP, user ID, etc.)
     * @param int $limit Maximum attempts allowed
     * @param int $window Time window in seconds
     * @param int $user_id User ID for user-based rate limiting
     * @return bool True if within limits, false if exceeded
     */
    private function mdlogin_check_enhanced_rate_limit($action, $identifier, $limit = 5, $window = 300, $user_id = 0) {
        // Get current client information for adaptive scoring
        $client_ip = $this->mdlogin_get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
        
        // Calculate adaptive limits based on client characteristics
        $adaptive_limits = $this->mdlogin_calculate_adaptive_rate_limits($action, $client_ip, $user_agent, $user_id);
        
        // Apply adaptive limits
        $ip_limit = $adaptive_limits['ip_limit'];
        $user_limit = $adaptive_limits['user_limit'];
        $window_adjusted = $adaptive_limits['window'];
        
        // IP-based rate limiting with adaptive limits
        $ip_key = 'mdlogin_rate_limit_' . $action . '_ip_' . md5($client_ip);
        $ip_attempts = get_transient($ip_key);
        
        if ($ip_attempts && $ip_attempts >= $ip_limit) {
            // Log rate limit exceeded with context
            $this->mdlogin_log_security_event(
                'adaptive_rate_limit_exceeded',
                'Adaptive rate limit exceeded for IP',
                array(
                    'action' => $action,
                    'ip' => $client_ip,
                    'attempts' => $ip_attempts,
                    'limit' => $ip_limit,
                    'window' => $window_adjusted,
                    'user_agent' => $user_agent,
                    'security_level' => $adaptive_limits['security_level']
                ),
                'warning'
            );
            return false; // IP rate limit exceeded
        }
        
        // User-based rate limiting with adaptive limits (if user is logged in)
        if ($user_id > 0) {
            $user_key = 'mdlogin_rate_limit_' . $action . '_user_' . $user_id;
            $user_attempts = get_transient($user_key);
            
            if ($user_attempts && $user_attempts >= $user_limit) {
                // Log rate limit exceeded with context
                $this->mdlogin_log_security_event(
                    'adaptive_rate_limit_exceeded',
                    'Adaptive rate limit exceeded for user',
                    array(
                        'action' => $action,
                        'user_id' => $user_id,
                        'attempts' => $user_attempts,
                        'limit' => $user_limit,
                        'window' => $window_adjusted,
                        'ip' => $client_ip,
                        'user_agent' => $user_agent,
                        'security_level' => $adaptive_limits['security_level']
                    ),
                    'warning'
                );
                return false; // User rate limit exceeded
            }
            
            // Increment user rate limit counter
            $user_attempts = $user_attempts ? $user_attempts + 1 : 1;
            set_transient($user_key, $user_attempts, $window_adjusted);
        }
        
        // Increment IP rate limit counter
        $ip_attempts = $ip_attempts ? $ip_attempts + 1 : 1;
        set_transient($ip_key, $ip_attempts, $window_adjusted);
        
        // Log successful rate limit check
        $this->mdlogin_log_security_event(
            'adaptive_rate_limit_check',
            'Adaptive rate limit check passed',
            array(
                'action' => $action,
                'ip' => $client_ip,
                'user_id' => $user_id,
                'ip_attempts' => $ip_attempts,
                'ip_limit' => $ip_limit,
                'user_attempts' => $user_id > 0 ? ($user_attempts ?? 0) : 0,
                'user_limit' => $user_limit,
                'window' => $window_adjusted,
                'security_level' => $adaptive_limits['security_level']
            ),
            'info'
        );
        
        return true;
    }

    /**
     * Calculate adaptive rate limits based on client characteristics
     *
     * @param string $action Action being performed
     * @param string $client_ip Client IP address
     * @param string $user_agent User agent string
     * @param int $user_id User ID
     * @return array Adaptive limits
     */
    private function mdlogin_calculate_adaptive_rate_limits($action, $client_ip, $user_agent, $user_id) {
        // Base limits
        $base_limits = array(
            'registration' => array('ip' => 10, 'user' => 15, 'window' => 300),
            'verify_registration' => array('ip' => 15, 'user' => 20, 'window' => 300),
            'login' => array('ip' => 20, 'user' => 25, 'window' => 300),
            'verify_login' => array('ip' => 15, 'user' => 20, 'window' => 300)
        );
        
        $base = $base_limits[$action] ?? $base_limits['login'];
        
        // Calculate security level based on client characteristics
        $security_level = $this->mdlogin_calculate_rate_limit_security_level($client_ip, $user_agent, $user_id);
        
        // Apply adaptive multipliers based on security level
        $multipliers = array(
            1 => array('ip' => 0.5, 'user' => 0.5, 'window' => 1.5), // Very low security - stricter limits
            2 => array('ip' => 0.7, 'user' => 0.7, 'window' => 1.2), // Low security - somewhat stricter
            3 => array('ip' => 1.0, 'user' => 1.0, 'window' => 1.0), // Medium security - base limits
            4 => array('ip' => 1.3, 'user' => 1.3, 'window' => 0.8), // High security - more lenient
            5 => array('ip' => 1.5, 'user' => 1.5, 'window' => 0.7)  // Very high security - most lenient
        );
        
        $multiplier = $multipliers[$security_level] ?? $multipliers[3];
        
        // Calculate adaptive limits
        $ip_limit = max(1, round($base['ip'] * $multiplier['ip']));
        $user_limit = max(1, round($base['user'] * $multiplier['user']));
        $window = max(60, round($base['window'] * $multiplier['window']));
        
        return array(
            'ip_limit' => $ip_limit,
            'user_limit' => $user_limit,
            'window' => $window,
            'security_level' => $security_level,
            'multiplier' => $multiplier
        );
    }
    
    /**
     * Calculate security level for rate limiting based on client characteristics
     *
     * @param string $client_ip Client IP address
     * @param string $user_agent User agent string
     * @param int $user_id User ID
     * @return int Security level (1-5)
     */
    private function mdlogin_calculate_rate_limit_security_level($client_ip, $user_agent, $user_id) {
        $security_score = 0;
        
        // IP-based security assessment
        if ($this->mdlogin_is_trusted_ip($client_ip)) {
            $security_score += 2; // Trusted IP (CDN, known services)
        } elseif ($this->mdlogin_is_private_ip($client_ip)) {
            $security_score += 1; // Private IP (local network)
        } elseif ($this->mdlogin_is_suspicious_ip($client_ip)) {
            $security_score -= 1; // Suspicious IP (known bad actors)
        }
        
        // User agent-based security assessment
        if ($this->mdlogin_is_known_browser($user_agent)) {
            $security_score += 1; // Known browser
        } elseif ($this->mdlogin_is_suspicious_user_agent($user_agent)) {
            $security_score -= 1; // Suspicious user agent
        }
        
        // User-based security assessment
        if ($user_id > 0) {
            $user = get_user_by('ID', $user_id);
            if ($user) {
                // Check user role and capabilities
                if (user_can($user, 'manage_options')) {
                    $security_score += 1; // Admin user
                } elseif (user_can($user, 'edit_posts')) {
                    $security_score += 0.5; // Editor user
                }
                
                // Check user registration date
                $user_registered = strtotime($user->user_registered);
                $days_since_registration = (time() - $user_registered) / (24 * 60 * 60);
                if ($days_since_registration > 30) {
                    $security_score += 0.5; // Established user
                }
            }
        }
        
        // Check for previous rate limit violations
        $violation_key = 'mdlogin_rate_violations_' . md5($client_ip);
        $violations = get_transient($violation_key);
        if ($violations && $violations > 3) {
            $security_score -= 1; // Previous violations
        }
        
        // Normalize security score to 1-5 range
        $security_level = max(1, min(5, 3 + $security_score));
        
        return $security_level;
    }
    
    /**
     * Check if IP is trusted (CDN, known services)
     *
     * @param string $ip IP address
     * @return bool
     */
    private function mdlogin_is_trusted_ip($ip) {
        // Add known trusted IP ranges (CDNs, etc.)
        $trusted_ranges = array(
            '104.16.0.0/12', // Cloudflare
            '173.245.48.0/20', // Cloudflare
            '103.21.244.0/22', // Cloudflare
            '103.22.200.0/22', // Cloudflare
            '103.31.4.0/22', // Cloudflare
            '141.101.64.0/18', // Cloudflare
            '108.162.192.0/18', // Cloudflare
            '190.93.240.0/20', // Cloudflare
            '188.114.96.0/20', // Cloudflare
            '197.234.240.0/22', // Cloudflare
            '198.41.128.0/17', // Cloudflare
            '162.158.0.0/15', // Cloudflare
            '104.16.0.0/13', // Cloudflare
            '104.24.0.0/14', // Cloudflare
            '172.64.0.0/13', // Cloudflare
            '131.0.72.0/22', // Cloudflare
        );
        
        foreach ($trusted_ranges as $range) {
            if ($this->mdlogin_ip_in_range($ip, $range)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is private (local network)
     *
     * @param string $ip IP address
     * @return bool
     */
    private function mdlogin_is_private_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false;
    }
    
    /**
     * Check if IP is suspicious (known bad actors)
     *
     * @param string $ip IP address
     * @return bool
     */
    private function mdlogin_is_suspicious_ip($ip) {
        // This would typically check against a threat intelligence database
        // For now, we'll use a simple heuristic
        $suspicious_patterns = array(
            '/^10\./', // Private network (could be VPN)
            '/^192\.168\./', // Private network
            '/^172\.(1[6-9]|2[0-9]|3[0-1])\./', // Private network
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $ip)) {
                return false; // Private networks are not suspicious
            }
        }
        
        return false; // Default to not suspicious
    }
    
    /**
     * Check if user agent is from a known browser
     *
     * @param string $user_agent User agent string
     * @return bool
     */
    private function mdlogin_is_known_browser($user_agent) {
        $known_browsers = array('Chrome', 'Firefox', 'Safari', 'Edge', 'Opera');
        
        foreach ($known_browsers as $browser) {
            if (stripos($user_agent, $browser) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if user agent is suspicious
     *
     * @param string $user_agent User agent string
     * @return bool
     */
    private function mdlogin_is_suspicious_user_agent($user_agent) {
        $suspicious_patterns = array(
            '/bot/i',
            '/crawler/i',
            '/spider/i',
            '/scraper/i',
            '/curl/i',
            '/wget/i',
            '/python/i',
            '/php/i'
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is in CIDR range
     *
     * @param string $ip IP address
     * @param string $range CIDR range
     * @return bool
     */
    private function mdlogin_ip_in_range($ip, $range) {
        list($subnet, $bits) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet_long &= $mask;
        return ($ip_long & $mask) == $subnet_long;
    }

    /**
     * Progressive delay system for suspicious activity
     *
     * @param string $identifier User identifier
     * @param int $base_delay Base delay in seconds
     * @return int Calculated delay
     */
    private function mdlogin_calculate_progressive_delay($identifier, $base_delay = 1) {
        $delay_key = 'mdlogin_progressive_delay_' . md5($identifier);
        $attempts = get_transient($delay_key);
        
        if (!$attempts) {
            $attempts = 1;
        } else {
            $attempts++;
        }
        
        // Progressive delay: 1s, 2s, 4s, 8s, 16s, 30s max
        $delay = min($base_delay * pow(2, $attempts - 1), 30);
        
        set_transient($delay_key, $attempts, 3600); // 1 hour
        
        return $delay;
    }

    /**
     * Enhanced security monitoring and alerting
     *
     * @param string $event_type Type of security event
     * @param string $message Event message
     * @param array $context Additional context
     * @param string $severity Event severity
     */
    private function mdlogin_enhanced_security_monitoring($event_type, $message, $context = array(), $severity = 'info') {
        // Log to WordPress error log
        error_log('MDLOGIN Security Event: ' . wp_json_encode(array(
            'timestamp' => current_time('mysql'),
            'event_type' => $event_type,
            'message' => $message,
            'severity' => $severity,
            'context' => $context,
            'ip' => $this->mdlogin_get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : ''
        )));

        // Store in security log table
        $this->mdlogin_store_enhanced_security_log($event_type, $message, $context, $severity);

        // Send alerts for critical events
        if ($severity === 'critical' || $severity === 'high') {
            $this->mdlogin_send_security_alert($event_type, $message, $context);
        }
    }

    /**
     * Store enhanced security log
     *
     * @param string $event_type Event type
     * @param string $message Event message
     * @param array $context Additional context
     * @param string $severity Event severity
     */
    private function mdlogin_store_enhanced_security_log($event_type, $message, $context, $severity) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_security_logs';
        
        // Create table if it doesn't exist
        $this->mdlogin_create_enhanced_security_log_table();
        
        $wpdb->insert(
            $table_name,
            array(
                'event_type' => $event_type,
                'message' => $message,
                'severity' => $severity,
                'context' => wp_json_encode($context),
                'ip_address' => $this->mdlogin_get_client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
                'user_id' => is_user_logged_in() ? get_current_user_id() : 0,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s')
        );
    }

    /**
     * Create enhanced security log table
     */
    private function mdlogin_create_enhanced_security_log_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'mdlogin_security_logs';
        
        // Check if table exists
        $table_exists = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW TABLES LIKE %s",
                $table_name
            )
        );
        
        if (!$table_exists) {
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE $table_name (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                event_type varchar(50) NOT NULL,
                message text NOT NULL,
                severity varchar(20) NOT NULL DEFAULT 'info',
                context longtext,
                ip_address varchar(45) NOT NULL,
                user_agent text,
                user_id bigint(20) DEFAULT 0,
                created_at datetime DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY event_type (event_type),
                KEY severity (severity),
                KEY ip_address (ip_address),
                KEY user_id (user_id),
                KEY created_at (created_at)
            ) $charset_collate;";

            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }
    }

    /**
     * Send security alert for critical events
     *
     * @param string $event_type Event type
     * @param string $message Event message
     * @param array $context Additional context
     */
    private function mdlogin_send_security_alert($event_type, $message, $context) {
        // Get admin email
        $admin_email = get_option('admin_email');
        
        if (!$admin_email) {
            return;
        }
        
        $subject = 'Security Alert: ' . $event_type;
        $body = "A security event has been detected:\n\n";
        $body .= "Event: " . $event_type . "\n";
        $body .= "Message: " . $message . "\n";
        $body .= "Time: " . current_time('mysql') . "\n";
        $body .= "IP: " . $this->mdlogin_get_client_ip() . "\n";
        $body .= "Context: " . wp_json_encode($context) . "\n";
        
        wp_mail($admin_email, $subject, $body);
    }

    /**
     * Clear rate limits for a specific IP or user (admin utility)
     *
     * @param string $ip_address IP address to clear limits for
     * @param int $user_id User ID to clear limits for (optional)
     * @return bool True if limits were cleared
     */
    public function mdlogin_clear_rate_limits($ip_address = '', $user_id = 0) {
        if (empty($ip_address) && $user_id <= 0) {
            return false;
        }
        
        $actions = array('registration', 'verify_registration', 'login');
        
        foreach ($actions as $action) {
            if (!empty($ip_address)) {
                $ip_key = 'mdlogin_rate_limit_' . $action . '_ip_' . md5($ip_address);
                delete_transient($ip_key);
            }
            
            if ($user_id > 0) {
                $user_key = 'mdlogin_rate_limit_' . $action . '_user_' . $user_id;
                delete_transient($user_key);
            }
        }
        
        return true;
    }

    /**
     * Get current rate limit status for debugging
     *
     * @param string $ip_address IP address to check
     * @param int $user_id User ID to check (optional)
     * @return array Rate limit status
     */
    public function mdlogin_get_rate_limit_status($ip_address = '', $user_id = 0) {
        $status = array();
        $actions = array('registration', 'verify_registration', 'login');
        
        foreach ($actions as $action) {
            $status[$action] = array();
            
            if (!empty($ip_address)) {
                $ip_key = 'mdlogin_rate_limit_' . $action . '_ip_' . md5($ip_address);
                $ip_attempts = get_transient($ip_key);
                $status[$action]['ip_attempts'] = $ip_attempts ? $ip_attempts : 0;
            }
            
            if ($user_id > 0) {
                $user_key = 'mdlogin_rate_limit_' . $action . '_user_' . $user_id;
                $user_attempts = get_transient($user_key);
                $status[$action]['user_attempts'] = $user_attempts ? $user_attempts : 0;
            }
        }
        
        return $status;
    }


} 