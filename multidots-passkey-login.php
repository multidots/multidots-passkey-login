<?php
 /*
 * Plugin Name:       Multidots Passkey Login – Passwordless Authentication
 * Plugin URI:        https://www.multidots.com
 * Description:       Adds secure Passkey authentication using WebAuthn to WordPress login page. Users can register and login using their device's biometric authentication or PIN.
 * Version:           1.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Multidots
 * Author URI:        https://www.multidots.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       multidots-passkey-login
 * Domain Path:       /languages
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('MDLOGIN_PASSKEY_VERSION', '1.0');
define('MDLOGIN_PASSKEY_PLUGIN_FILE', __FILE__);
define('MDLOGIN_PASSKEY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('MDLOGIN_PASSKEY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MDLOGIN_PASSKEY_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Main plugin class
 * 
 * @since 1.0.0
 */
final class MDLOGIN_Passkey {

    /**
     * Plugin instance
     *
     * @var MDLOGIN_Passkey
     */
    private static $instance = null;

    /**
     * Get plugin instance
     *
     * @return MDLOGIN_Passkey
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
        // Check requirements first before any initialization
        if (!$this->mdlogin_check_requirements()) {
            return; // Stop initialization if requirements not met
        }
        
        $this->mdlogin_init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function mdlogin_init_hooks() {
        // Load dependencies
        add_action('plugins_loaded', array($this, 'mdlogin_load_dependencies'));
        
        // Initialize plugin
        add_action('init', array($this, 'mdlogin_init'));
        
        // Register activation and deactivation hooks
        register_activation_hook(__FILE__, array($this, 'mdlogin_activate'));
        register_deactivation_hook(__FILE__, array($this, 'mdlogin_deactivate'));
    }

    /**
     * Load plugin dependencies
     */
    public function mdlogin_load_dependencies() {
        // Load Composer autoloader
        if (file_exists(MDLOGIN_PASSKEY_PLUGIN_DIR . 'vendor/autoload.php')) {
            require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'vendor/autoload.php';
        } else {
            add_action('admin_notices', array($this, 'mdlogin_composer_notice'));
            return;
        }

        // Load plugin classes
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-loader.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-webauthn.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-credentials.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-api.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-shortcodes.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-profile.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'includes/class-mdlogin-passkey-i18n.php';
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'admin/class-mdlogin-passkey-admin.php';
    }

    /**
     * Initialize plugin
     */
    public function mdlogin_init() {
        // Handle session initialization for WP Engine compatibility
        $this->mdlogin_init_sessions();

        // Initialize plugin components
        MDLOGIN_Passkey_Loader::mdlogin_get_instance();
        MDLOGIN_Passkey_WebAuthn::mdlogin_get_instance();
        MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        MDLOGIN_Passkey_API::mdlogin_get_instance();
        MDLOGIN_Passkey_Shortcodes::mdlogin_get_instance();
        MDLOGIN_Passkey_Profile::mdlogin_get_instance();
        MDLOGIN_Passkey_I18n::mdlogin_get_instance();
        
        // Initialize admin if in admin area
        if (is_admin()) {
            MDLOGIN_Passkey_Admin::mdlogin_get_instance();
        }
    }

    /**
     * Initialize sessions with WP Engine compatibility
     */
    private function mdlogin_init_sessions() {
        // Check if we're on WP Engine
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }

        $is_wp_engine = defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false;
        
        if ($is_wp_engine) {
            // On WP Engine, avoid PHP sessions as they can cause conflicts
            // We'll rely entirely on our custom database sessions

        } else {
            // On other hosts, use PHP sessions as backup
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
        }
    }

    /**
     * Plugin activation
     */
    public function mdlogin_activate() {
        // Check requirements
        if (!$this->mdlogin_check_requirements()) {
            deactivate_plugins(plugin_basename(__FILE__));
            return;
        }

        // Create database tables if needed
        $this->mdlogin_create_tables();

        // Set default options
        $this->mdlogin_set_default_options();

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function mdlogin_deactivate() {
        // Clear scheduled events
        wp_clear_scheduled_hook('mdlogin_passkey_cleanup');

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Check plugin requirements
     *
     * @return bool
     */
    private function mdlogin_check_requirements() {
        // Check PHP version
        if (version_compare(PHP_VERSION, '8.1', '<')) {
            add_action('admin_notices', array($this, 'mdlogin_php_version_notice'));
            return false;
        }

        // Check WordPress version
        if (version_compare(get_bloginfo('version'), '6.0', '<')) {
            add_action('admin_notices', array($this, 'mdlogin_wp_version_notice'));
            return false;
        }

        // Check if HTTPS is enabled (recommended for WebAuthn)
        if (!is_ssl() && !is_admin()) {
            add_action('admin_notices', array($this, 'mdlogin_https_notice'));
        }

        return true;
    }

    /**
     * Create database tables
     */
    private function mdlogin_create_tables() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Create passkey sessions table
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
     * Set default options
     */
    private function mdlogin_set_default_options() {
        // Check if we're on WP Engine
        $http_host = '';
        if ( isset( $_SERVER['HTTP_HOST'] ) ) {
            $http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
        }

        $is_wp_engine = defined( 'WP_ENGINE' ) || strpos( $http_host, 'wpengine' ) !== false;
        
        $default_options = array(
            'enabled' => true,
            'require_https' => true,
            'session_timeout' => $is_wp_engine ? 600 : 300, // 10 minutes for WP Engine, 5 minutes for others
            'max_credentials_per_user' => 3,
            'prevent_duplicate_authenticators' => true,
            'allow_new_registrations' => false,
            'new_user_role' => 'subscriber',
            'wp_engine_compatibility' => $is_wp_engine, // Flag for WP Engine compatibility
        );

        add_option('mdlogin_passkey_settings', $default_options);
    }



    /**
     * PHP version notice
     */
    public function mdlogin_php_version_notice() {
        echo '<div class="notice notice-error is-dismissible">';
        echo '<p><strong>' . esc_html__( 'Passkey:', 'multidots-passkey-login' ) . '</strong> ';
        printf(
            /* translators: %s: Current PHP version */
            esc_html__( 'This plugin requires PHP 8.1 or higher. Your current version is %s.', 'multidots-passkey-login' ),
            esc_html( PHP_VERSION )
        );
        echo '</p></div>';
    }

    /**
     * WordPress version notice
     */
    public function mdlogin_wp_version_notice() {
        echo '<div class="notice notice-error is-dismissible">';
        echo '<p><strong>' . esc_html__('Passkey:', 'multidots-passkey-login') . '</strong> ';
        echo esc_html__('This plugin requires WordPress 6.0 or higher.', 'multidots-passkey-login') . '</p>';
        echo '</div>';
    }

    /**
     * Composer dependencies notice
     */
    public function mdlogin_composer_notice() {
        echo '<div class="notice notice-error is-dismissible">';
        echo '<p><strong>' . esc_html__('Passkey:', 'multidots-passkey-login') . '</strong> ';
        echo esc_html__('Required dependencies are missing. Please run composer install in the plugin directory.', 'multidots-passkey-login') . '</p>';
        echo '</div>';
    }

    /**
     * HTTPS notice
     */
    public function mdlogin_https_notice() {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('Passkey:', 'multidots-passkey-login') . '</strong> ';
        echo esc_html__('This plugin works best with HTTPS enabled. Please enable SSL for your site.', 'multidots-passkey-login') . '</p>';
        echo '</div>';
    }
}

/**
 * Get plugin instance
 *
 * @return MDLOGIN_Passkey
 */
function mdlogin_passkey() {
    return MDLOGIN_Passkey::mdlogin_get_instance();
}

// Initialize plugin
mdlogin_passkey(); 