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
            'permission_callback' => array($this, 'mdlogin_check_session_permissions'),
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
            'permission_callback' => array($this, 'mdlogin_check_session_permissions'),
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
            // Verify nonce
            if (!wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest')) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
            }

            $username = $request->get_param('username');
            $email = $request->get_param('email');
            $user = null;
            $is_new_user = false;
            


            // Get plugin settings
            $settings = get_option('mdlogin_passkey_settings', array());
            $allow_new_registrations = isset($settings['allow_new_registrations']) ? $settings['allow_new_registrations'] : false;

            // If user is logged in, allow registration with username or email
            if (is_user_logged_in()) {
                $user = wp_get_current_user();
                
                // If username is provided, verify it matches the logged-in user
                if (!empty($username)) {
                    if ($user->user_login !== $username) {
                        // Check if the provided username exists for another user
                        $existing_user = get_user_by('login', $username);
                        if ($existing_user && $existing_user->ID !== $user->ID) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => sprintf(
                                    /* translators: %s: Username */
                                    __('Username "%s" is already registered by another user.', 'multidots-passkey-login'),
                                    $username
                                )
                            ), 409);
                        } else {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => __('Username does not match your logged-in account.', 'multidots-passkey-login')
                            ), 400);
                        }
                    }
                }
                
                // If email is provided, verify it matches the logged-in user
                if (!empty($email)) {
                    if ($user->user_email !== $email) {
                        // Check if the provided email exists for another user
                        $existing_user = get_user_by('email', $email);
                        if ($existing_user && $existing_user->ID !== $user->ID) {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => sprintf(
                                    /* translators: %s: Email address */
                                    __('Email "%s" is already registered by another user.', 'multidots-passkey-login'),
                                    $email
                                )
                            ), 409);
                        } else {
                            return new WP_REST_Response(array(
                                'success' => false,
                                'error' => __('Email does not match your logged-in account.', 'multidots-passkey-login')
                            ), 400);
                        }
                    }
                }
                
                // If no username or email provided, use the logged-in user's info
                if (empty($username) && empty($email)) {
                    $username = $user->user_login;
                    $email = $user->user_email;
                }
            }
            // For users not logged in, check if they're existing users or new users
            elseif (!is_user_logged_in()) {
                $existing_user = null;
                
                // Try to find user by username
                if (!empty($username)) {
                    $existing_user = get_user_by('login', $username);
                }
                
                // If not found by username, try email
                if (!$existing_user && !empty($email)) {
                    $existing_user = get_user_by('email', $email);
                }
                
                // If existing user found, use them for passkey registration
                if ($existing_user) {
                    $user = $existing_user;
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

            return new WP_REST_Response(array(
                'success' => true,
                'session_id' => $session_id,
                'options' => $options_array
            ));

        } catch (Exception $e) {
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
            // Verify nonce
            if (!wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest')) {
                return new WP_REST_Response(array(
                    'success' => false,
                    'error' => __('Security check failed.', 'multidots-passkey-login')
                ), 403);
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

        return $session !== false;
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


} 