<?php
/**
 * Shortcodes Class
 * 
 * Handles shortcode functionality for passkey login and registration
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * MDLOGIN_Passkey_Shortcodes class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Shortcodes {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_Shortcodes
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_Shortcodes
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
        // Register shortcodes
        add_shortcode('mdlogin_passkey_login', array($this, 'mdlogin_login_shortcode'));
        add_shortcode('mdlogin_passkey_register', array($this, 'mdlogin_register_shortcode'));
        
        // Enqueue scripts for shortcodes
        add_action('wp_enqueue_scripts', array($this, 'mdlogin_enqueue_shortcode_scripts'));
    }

    /**
     * Enqueue scripts for shortcodes
     */
    public function mdlogin_enqueue_shortcode_scripts() {
        // Only enqueue if shortcodes are present on the page
        global $post;
        
        if (is_a($post, 'WP_Post') && (
            has_shortcode($post->post_content, 'mdlogin_passkey_login') ||
            has_shortcode($post->post_content, 'mdlogin_passkey_register')
        )) {
            $this->mdlogin_enqueue_scripts();
        }
    }

    /**
     * Enqueue scripts and styles
     */
    private function mdlogin_enqueue_scripts() {
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
                'registerSuccess' => __('Passkey registered successfully!', 'multidots-passkey-login'),
            'newUserRegisterSuccess' => __('Account created and passkey registered successfully! You can now login with your passkey.', 'multidots-passkey-login'),
                'loginSuccess' => __('Login successful!', 'multidots-passkey-login'),
                'error' => __('An error occurred. Please try again.', 'multidots-passkey-login'),
                'notSupported' => __('Passkeys are not supported in this browser or device.', 'multidots-passkey-login'),
                'usernameRequired' => __('Please enter a username or email for passkey registration.', 'multidots-passkey-login'),
            'emailRequired' => __('Username or email is required for registration.', 'multidots-passkey-login'),
            'usernameOrEmailRequired' => __('Username or email is required for new user registration.', 'multidots-passkey-login'),
            'invalidEmail' => __('Please enter a valid email address.', 'multidots-passkey-login'),
            'usernameExists' => __('This username is already registered. Please try a different username.', 'multidots-passkey-login'),
            'emailExists' => __('This email is already registered. Please login with your existing account or use a different email.', 'multidots-passkey-login'),
            'alreadyHasPasskey' => __('You already have passkey credentials registered. Please login with your existing passkey.', 'multidots-passkey-login'),
                'creatingPasskey' => __('Creating passkey... Please follow your device\'s instructions.', 'multidots-passkey-login'),
                'authenticating' => __('Authenticating with passkey... Please follow your device\'s instructions.', 'multidots-passkey-login'),
                'startingRegistration' => __('Starting passkey registration...', 'multidots-passkey-login'),
                'startingLogin' => __('Starting passkey login...', 'multidots-passkey-login'),
            ),
            'settings' => array(
    
                'sessionTimeout' => isset($settings['session_timeout']) ? $settings['session_timeout'] : 300,
            )
        ));
    }

    /**
     * Login shortcode
     *
     * @param array $atts Shortcode attributes
     * @return string
     */
    public function mdlogin_login_shortcode($atts) {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only show if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled']) {
            return '';
        }

        // Parse attributes
        $atts = shortcode_atts(array(
            'title' => __('Passkey', 'multidots-passkey-login'),
            'description' => __('Use your device\'s biometric authentication or PIN for secure login', 'multidots-passkey-login'),
            'button_text' => __('Login with Passkey', 'multidots-passkey-login'),
            'redirect_url' => '',
            'class' => '',
        ), $atts, 'mdlogin_passkey_login');

        // Check if user is already logged in
        if (is_user_logged_in()) {
            $current_user = wp_get_current_user();
            return sprintf(
                '<div class="mdlogin-logged-in %s">
                    <p>%s</p>
                    <a href="%s" class="mdlogin-button mdlogin-button-secondary">%s</a>
                </div>',
                esc_attr($atts['class']),
                /* translators: %s: User display name */
                sprintf(__('You are already logged in as %s.', 'multidots-passkey-login'), esc_html($current_user->display_name)),
                esc_url(wp_logout_url()),
                __('Logout', 'multidots-passkey-login')
            );
        }

        // Generate unique ID for this shortcode instance
        $unique_id = 'mdlogin-' . uniqid();

        ob_start();
        ?>
        <div class="mdlogin-container mdlogin-shortcode <?php echo esc_attr($atts['class']); ?>" id="<?php echo esc_attr($unique_id); ?>">
    
            <div class="mdlogin-buttons">
                <button type="button" id="mdlogin" class="mdlogin-button mdlogin-button-primary" 
                        data-redirect="<?php echo esc_attr($atts['redirect_url']); ?>">
                    <span class="mdlogin-icon">🔐</span>
                    <?php echo esc_html($atts['button_text']); ?>
                </button>
            </div>
            
            <!-- Status messages -->
            <div id="mdlogin-status" class="mdlogin-status" style="display: none;"></div>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Register shortcode
     *
     * @param array $atts Shortcode attributes
     * @return string
     */
    public function mdlogin_register_shortcode($atts) {
        // Get plugin settings
        $settings = get_option('mdlogin_passkey_settings', array());
        
        // Only show if plugin is enabled
        if (!isset($settings['enabled']) || !$settings['enabled'] || !is_user_logged_in()) {
            return '';
        }

        // Parse attributes
        $atts = shortcode_atts(array(
            'title' => __('Register Passkey', 'multidots-passkey-login'),
            'description' => __('Create a new passkey for secure authentication', 'multidots-passkey-login'),
            'button_text' => __('Register Passkey', 'multidots-passkey-login'),
            'redirect_url' => '',
            'class' => '',
        ), $atts, 'mdlogin_passkey_register');

        // Generate unique ID for this shortcode instance
        $unique_id = 'mdlogin-register-' . uniqid();

        ob_start();
        ?>
        <div class="mdlogin-container mdlogin-shortcode <?php echo esc_attr($atts['class']); ?>" id="<?php echo esc_attr($unique_id); ?>">

            
            <!-- Username or Email field for registration -->
            <?php if (!is_user_logged_in()): ?>
            <div class="mdlogin-username-field">
                <input 
                    id="mdlogin-username"
                    name="mdlogin_passkey_username"
                    type="text" 
                    class="mdlogin-input mdlogin-username-input" 
                    placeholder="<?php echo esc_attr($atts['username_placeholder']); ?>"
                    required
                >
            </div>
            <?php endif; ?>

            <div class="mdlogin-buttons">
                <button type="button" id="mdlogin-register" class="mdlogin-button mdlogin-button-secondary">
                    <span class="mdlogin-icon">🔑</span>
                    <?php esc_html_e('Register Passkey', 'multidots-passkey-login'); ?>
                </button>
            </div>    
            
            <!-- Status messages -->
            <div id="mdlogin-status" class="mdlogin-status" style="display: none;"></div>
        </div>
        <?php
        return ob_get_clean();
    }

    /**
     * Get available shortcodes for display
     *
     * @return array
     */
    public static function mdlogin_get_available_shortcodes() {
        return array(
            'login' => array(
                'shortcode' => '[mdlogin_passkey_login]',
                'description' => __('Displays a passkey login button', 'multidots-passkey-login'),
                'attributes' => array(
                    'title' => __('Custom title for the login section', 'multidots-passkey-login'),
                    'description' => __('Custom description text', 'multidots-passkey-login'),
                    'button_text' => __('Custom button text', 'multidots-passkey-login'),
                    'redirect_url' => __('URL to redirect after successful login', 'multidots-passkey-login'),
                    'class' => __('Additional CSS classes', 'multidots-passkey-login'),
                ),
                'example' => '[mdlogin_passkey_login title="Secure Login" button_text="Login with Passkey" redirect_url="/dashboard"]'
            ),
            'register' => array(
                'shortcode' => '[mdlogin_passkey_register]',
                'description' => __('Displays a passkey registration form', 'multidots-passkey-login'),
                'attributes' => array(
                    'title' => __('Custom title for the registration section', 'multidots-passkey-login'),
                    'description' => __('Custom description text', 'multidots-passkey-login'),
                    'button_text' => __('Custom button text', 'multidots-passkey-login'),
                    'username_placeholder' => __('Placeholder text for username field', 'multidots-passkey-login'),
                    'redirect_url' => __('URL to redirect after successful registration', 'multidots-passkey-login'),
                    'class' => __('Additional CSS classes', 'multidots-passkey-login'),
                ),
                'example' => '[mdlogin_passkey_register title="Create Passkey" button_text="Register New Passkey" redirect_url="/profile"]'
            )
        );
    }
} 