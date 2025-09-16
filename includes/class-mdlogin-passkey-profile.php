<?php
/**
 * Profile Class
 * 
 * Handles passkey functionality on WordPress user profile page
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 * 
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * MDLOGIN_Passkey_Profile class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Profile {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_Profile
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_Profile
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
        // Add passkey section to user profile page
        add_action('show_user_profile', array($this, 'mdlogin_add_passkey_section'));
        add_action('edit_user_profile', array($this, 'mdlogin_add_passkey_section'));
        
        // Enqueue scripts and styles for profile page
        add_action('admin_enqueue_scripts', array($this, 'mdlogin_enqueue_profile_scripts'));
        
        // AJAX handlers for profile actions
        add_action('wp_ajax_mdlogin_passkey_profile_register', array($this, 'mdlogin_ajax_register_passkey'));
        add_action('wp_ajax_mdlogin_passkey_profile_verify', array($this, 'mdlogin_ajax_verify_registration'));
        add_action('wp_ajax_mdlogin_passkey_profile_delete', array($this, 'mdlogin_ajax_delete_passkey'));
        add_action('wp_ajax_mdlogin_passkey_profile_get_credentials', array($this, 'mdlogin_ajax_get_credentials'));
    }

    /**
     * Enqueue scripts and styles for profile page
     *
     * @param string $hook_suffix Current admin page
     */
    public function mdlogin_enqueue_profile_scripts($hook_suffix) {
        // Only load on profile.php page
        if ($hook_suffix !== 'profile.php' && $hook_suffix !== 'user-edit.php') {
            return;
        }

        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only enqueue if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return;
        }

        // Enqueue CSS
        wp_enqueue_style(
            'mdlogin-profile',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/css/mdlogin-passkey.css',
            array(),
            MDLOGIN_PASSKEY_VERSION
        );

        // Enqueue JavaScript
        wp_enqueue_script(
            'mdlogin-profile',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/js/mdlogin-profile.js',
            array('jquery'),
            MDLOGIN_PASSKEY_VERSION,
            true
        );

        // Localize script with AJAX data
        wp_localize_script('mdlogin-profile', 'mdPasskeyProfile', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'restUrl' => rest_url('mdlogin/v1/'),
            'nonce' => wp_create_nonce('wp_rest'),
            'profileNonce' => wp_create_nonce('mdlogin_passkey_profile_nonce'),
            'strings' => array(
                'registerSuccess' => __('Passkey registered successfully!', 'multidots-passkey-login'),
                'deleteSuccess' => __('Passkey deleted successfully!', 'multidots-passkey-login'),
                'error' => __('An error occurred. Please try again.', 'multidots-passkey-login'),
                'notSupported' => __('Passkeys are not supported in this browser or device.', 'multidots-passkey-login'),
                'creatingPasskey' => __('Creating passkey... Please follow your device\'s instructions.', 'multidots-passkey-login'),
                'startingRegistration' => __('Starting passkey registration...', 'multidots-passkey-login'),
                'confirmDelete' => __('Are you sure you want to delete this passkey?', 'multidots-passkey-login'),
                'maxCredentialsReached' => __('You have reached the maximum number of passkeys allowed.', 'multidots-passkey-login'),
            ),
            'settings' => array(
                'sessionTimeout' => isset($settings['session_timeout']) ? $settings['session_timeout'] : 300,
                'maxCredentials' => isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3,
            )
        ));
    }

    /**
     * Add passkey section to user profile page
     *
     * @param WP_User $user User object
     */
    public function mdlogin_add_passkey_section($user) {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only show if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return;
        }

        // Check if current user can edit this profile
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }

        // Get user's current credentials
        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $has_credentials = $credentials->mdlogin_user_has_credentials($user->ID);
        $current_credential_count = $credentials->mdlogin_get_user_credential_count($user->ID);
        $max_credentials = isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3;
        $can_register = $current_credential_count < $max_credentials;

        ?>
        <h2><?php esc_html_e('Passkey Management', 'multidots-passkey-login'); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label><?php esc_html_e('Passkey Status', 'multidots-passkey-login'); ?></label>
                </th>
                <td>
                    <?php if ($has_credentials): ?>
                        <span class="mdlogin-status-active">
                            <span class="dashicons dashicons-yes-alt"></span>
                            <?php 
                            printf(
                                /* translators: 1: Current number of registered passkeys, 2: Maximum allowed passkeys. */
                                esc_html__(
                                    'Active (%1$d of %2$d passkeys registered)',
                                    'multidots-passkey-login'
                                ),
                                esc_html($current_credential_count),
                                esc_html($max_credentials)
                            );
                            ?>
                        </span>
                    <?php else: ?>
                        <span class="mdlogin-status-inactive">
                            <span class="dashicons dashicons-no-alt"></span>
                            <?php esc_html_e('No passkeys registered', 'multidots-passkey-login'); ?>
                        </span>
                    <?php endif; ?>
                </td>
            </tr>
            
            <?php if ($can_register): ?>
            <tr>
                <th scope="row">
                    <label><?php esc_html_e('Register New Passkey', 'multidots-passkey-login'); ?></label>
                </th>
                <td>
                    <button type="button" id="mdlogin-register-profile" class="button button-secondary">
                        <span class="dashicons dashicons-admin-network"></span>
                        <?php esc_html_e('Register New Passkey', 'multidots-passkey-login'); ?>
                    </button>
                    <p class="description">
                        <?php esc_html_e('Register a new passkey for secure authentication. You can use your device\'s biometric authentication or PIN.', 'multidots-passkey-login'); ?>
                    </p>
                </td>
            </tr>
            <?php else: ?>
            <tr>
                <th scope="row">
                    <label><?php esc_html_e('Passkey Limit', 'multidots-passkey-login'); ?></label>
                </th>
                <td>
                    <span class="mdlogin-limit-reached">
                        <span class="dashicons dashicons-warning"></span>
                        <?php 
                        printf(
                             /* translators: %d: Maximum number of passkeys allowed */
                            esc_html__('You have reached the maximum limit of %d passkeys. Please delete an existing passkey before registering a new one.', 'multidots-passkey-login'),
                            esc_html($max_credentials)
                        ); 
                        ?>
                    </span>
                </td>
            </tr>
            <?php endif; ?>
        </table>

        <!-- Status messages -->
        <div id="mdlogin-profile-status" class="mdlogin-status" style="display: none;"></div>
        <?php
    }

    /**
     * AJAX handler for registering passkey from profile page
     */
    public function mdlogin_ajax_register_passkey() {
        try {
            // Verify nonce
            if (
                ! wp_verify_nonce(
                    sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                    'mdlogin_passkey_profile_nonce'
                )
            ) {
                wp_send_json_error(
                    array(
                        'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                    )
                );
            }

            // Check if user is logged in
            if (!is_user_logged_in()) {
                wp_send_json_error(array('message' => __('User not logged in.', 'multidots-passkey-login')));
            }

            $current_user = wp_get_current_user();
            
            // Check if user can register more credentials
            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            $current_credential_count = $credentials->mdlogin_get_user_credential_count($current_user->ID);
            
            $settings = get_option('mdlogin_passkey_settings', array());
            $max_credentials = isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3;
            
            if ($current_credential_count >= $max_credentials) {
                wp_send_json_error(array('message' => __('You have reached the maximum number of passkeys allowed.', 'multidots-passkey-login')));
            }

            // Create user entity
            $webauthn = MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
            
            // Test if WebAuthn is working
            if (!$webauthn) {
                wp_send_json_error(array('message' => __('WebAuthn system not available.', 'multidots-passkey-login')));
            }
            
            $user_entity = $webauthn->mdlogin_create_user_entity($current_user);

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
                        'id' => base64_encode($credential->getId()),
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

            $loader->mdlogin_store_session($session_id, $current_user->ID, $creation_options->getChallenge(), $options_data);

            // Convert options to array for JSON serialization
            $options_array = $webauthn->mdlogin_creation_options_to_array($creation_options);

            wp_send_json_success(array(
                'session_id' => $session_id,
                'options' => $options_array
            ));

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => __('Failed to start registration.', 'multidots-passkey-login'),
                'debug' => array(
                    'error' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine()
                )
            ));
        } catch (Error $e) {
            wp_send_json_error(array(
                'message' => __('A system error occurred during registration.', 'multidots-passkey-login'),
                'debug' => array(
                    'error' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine()
                )
            ));
        }
    }

    /**
     * AJAX handler for verifying passkey registration from profile page
     */
    public function mdlogin_ajax_verify_registration() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_profile_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }


        // Check if user is logged in
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => __('User not logged in.', 'multidots-passkey-login')));
        }

        $current_user = wp_get_current_user();

        $data = array();

        $raw_input = filter_input( INPUT_POST, 'credential_data', FILTER_UNSAFE_RAW );

        if ( null !== $raw_input ) {
            $decoded = json_decode( wp_unslash( $raw_input ), true );

            if ( is_array( $decoded ) ) {
                array_walk_recursive(
                    $decoded,
                    function ( &$value ) {
                        $value = sanitize_text_field( $value );
                    }
                );
                $data = $decoded;
            }
        }
    
        if (!$data || !isset($data['session_id'])) {
            wp_send_json_error(array('message' => __('Invalid request data.', 'multidots-passkey-login')));
        }

        try {
            // Get session data
            $loader = MDLOGIN_Passkey_Loader::mdlogin_get_instance();
            $session = $loader->mdlogin_get_session($data['session_id']);
            
            if (!$session) {
                wp_send_json_error(array('message' => __('Registration session expired or not found.', 'multidots-passkey-login')));
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
                wp_send_json_error(array('message' => __('Could not determine user for registration.', 'multidots-passkey-login')));
            }
            
            // Detect authenticator information
            $api = MDLOGIN_Passkey_API::mdlogin_get_instance();
            $authenticator_info = $api->mdlogin_detect_authenticator_from_credential($credential_source);
            
            // Save credential with authenticator information
            $credentials->saveCredentialSource($credential_source, $authenticator_info);

            // Delete session
            $loader->mdlogin_delete_session($data['session_id']);

            wp_send_json_success(array(
                'message' => __('Passkey registered successfully.', 'multidots-passkey-login')
            ));

        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => __('Registration verification failed.', 'multidots-passkey-login'),
                'debug' => array(
                    'error' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine()
                )
            ));
        } catch (Error $e) {
            wp_send_json_error(array(
                'message' => __('A system error occurred during verification.', 'multidots-passkey-login'),
                'debug' => array(
                    'error' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine()
                )
            ));
        }
    }

    /**
     * AJAX handler for deleting passkey from profile page
     */
    public function mdlogin_ajax_delete_passkey() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_profile_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }


        // Check if user is logged in
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => __('User not logged in.', 'multidots-passkey-login')));
        }

        $current_user = wp_get_current_user();
        $credential_id = isset( $_POST['credential_id'] )
            ? sanitize_text_field( wp_unslash( $_POST['credential_id'] ) )
            : '';
        
        if (empty($credential_id)) {
            wp_send_json_error(array('message' => __('Invalid credential ID.', 'multidots-passkey-login')));
        }

        // Delete credential directly using the credentials class
        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials($current_user->ID);
        
        foreach ($user_credentials as $credential) {
            if ($credential instanceof \Webauthn\PublicKeyCredentialSource) {
                $credential_id_encoded = base64_encode($credential->getPublicKeyCredentialId());
                $credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id_encoded, '='));
                
                if ($credential_id_url === $credential_id) {
                    $credentials->deleteCredentialSource($credential);
                    wp_send_json_success(array('message' => __('Credential deleted successfully.', 'multidots-passkey-login')));
                }
            }
        }

        wp_send_json_error(array('message' => __('Credential not found.', 'multidots-passkey-login')));
    }

    /**
     * AJAX handler for getting user credentials from profile page
     */
    public function mdlogin_ajax_get_credentials() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_profile_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }

        // Check if user is logged in
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => __('User not logged in.', 'multidots-passkey-login')));
        }

        $current_user = wp_get_current_user();
        
        // Get user credentials directly from the credentials class
        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials_for_display($current_user->ID);
        
        wp_send_json_success(array(
            'credentials' => $user_credentials
        ));
    }
} 