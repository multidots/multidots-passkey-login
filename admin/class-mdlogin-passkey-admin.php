<?php
/**
 * Admin Class
 * 
 * Handles admin panel functionality and settings
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * MDLOGIN_Passkey_Admin class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Admin {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_Admin
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_Admin
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
        // Add admin menu
        add_action('admin_menu', array($this, 'mdlogin_add_admin_menu'));
        
        // Add admin scripts and styles
        add_action('admin_enqueue_scripts', array($this, 'mdlogin_enqueue_admin_scripts'));
        add_action( 'admin_enqueue_scripts', array( $this, 'mdlogin_enqueue_admin_styles' ) );

        // Register settings
        add_action('admin_init', array($this, 'mdlogin_register_settings'));
        
        // Add settings link to plugins page
        add_filter('plugin_action_links_' . MDLOGIN_PASSKEY_PLUGIN_BASENAME, array($this, 'mdlogin_add_settings_link'));
        
        // AJAX handlers for admin actions
        add_action('wp_ajax_mdlogin_passkey_get_user_credentials', array($this, 'mdlogin_ajax_get_user_credentials'));
        add_action('wp_ajax_mdlogin_passkey_delete_credential', array($this, 'mdlogin_ajax_delete_credential'));
        add_action('wp_ajax_mdlogin_passkey_delete_all_credentials', array($this, 'mdlogin_ajax_delete_all_credentials'));
    }

    /**
     * Add admin menu
     */
    public function mdlogin_add_admin_menu() {
        add_menu_page(
            __('Passkey Settings', 'multidots-passkey-login'), 
            __('Passkey', 'multidots-passkey-login'),
            'manage_options',
            'mdlogin-settings',
            array($this, 'mdlogin_settings_page'),
            'dashicons-admin-network',
            25
        );

        // Override the auto-created submenu item (to change label from "Passkey" to "Setting")
        add_submenu_page(
            'mdlogin-settings',
            __('Passkey Settings', 'multidots-passkey-login'),
            __('Setting', 'multidots-passkey-login'), // This changes the submenu label
            'manage_options',
            'mdlogin-settings', // same slug as parent
            array($this, 'mdlogin_settings_page')
        );

        add_submenu_page(
            'mdlogin-settings',
            __('Passkey Management', 'multidots-passkey-login'),
            __('Passkeys', 'multidots-passkey-login'),
            'manage_options',
            'mdlogin-management',
            array($this, 'mdlogin_admin_page')
        );
    }

    /**
     * Enqueue admin scripts and styles
     *
     * @param string $hook_suffix Current admin page
     */
    public function mdlogin_enqueue_admin_scripts($hook_suffix) {
        // Only load on our admin pages
        if (!in_array($hook_suffix, array('passkey-login_page_mdlogin-management'))) {
            return;
        }

        wp_enqueue_script(
            'mdlogin-admin',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/js/mdlogin-admin.js',
            array('jquery'),
            MDLOGIN_PASSKEY_VERSION,
            true
        );

        wp_localize_script('mdlogin-admin', 'mdPasskeyAdmin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('mdlogin_passkey_admin_nonce'),
            'strings' => array(
                'confirmDelete' => __('Are you sure you want to delete this credential?', 'multidots-passkey-login'),
                'deleteSuccess' => __('Credential deleted successfully.', 'multidots-passkey-login'),
                'deleteError' => __('Failed to delete credential.', 'multidots-passkey-login'),
                'loadError' => __('Failed to load credentials.', 'multidots-passkey-login'),
            )
        ));

        wp_enqueue_style(
            'mdlogin-admin',
            MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/css/mdlogin-admin.css',
            array(),
            MDLOGIN_PASSKEY_VERSION
        );
    }

    	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @param string $hook_suffix The current admin page.
	 * @since    1.0
	 */
    public function mdlogin_enqueue_admin_styles( $hook_suffix ) {

        if ( 'toplevel_page_mdlogin-settings' === $hook_suffix || 'passkey_page_mdlogin-management' === $hook_suffix) {
            wp_enqueue_script(
                'mdlogin-admin',
                MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/js/mdlogin-admin.js',
                array('jquery'),
                MDLOGIN_PASSKEY_VERSION,
                true
            );

            wp_register_style( 'mdlogin-settings-style', MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/css/mdlogin-admin.css', array(), MDLOGIN_PASSKEY_VERSION );
            wp_enqueue_style( 'mdlogin-settings-style' );
        }
    }

    /**
     * Register settings
     */
    public function mdlogin_register_settings() {
        register_setting('mdlogin_passkey_settings', 'mdlogin_passkey_settings', array(
            'sanitize_callback' => array($this, 'mdlogin_sanitize_settings')
        ));

        add_settings_section(
            'mdlogin_passkey_general',
            __('General Settings', 'multidots-passkey-login'),
            array($this, 'mdlogin_settings_section_callback'),
            'mdlogin_passkey_settings'
        );

        add_settings_field(
            'enabled',
            __('Enable Passkey', 'multidots-passkey-login'),
            array($this, 'mdlogin_checkbox_field_callback'),
            'mdlogin_passkey_settings',
            'mdlogin_passkey_general',
            array('field' => 'enabled')
        );

        add_settings_field(
            'require_https',
            __('Require HTTPS', 'multidots-passkey-login'),
            array($this, 'mdlogin_checkbox_field_callback'),
            'mdlogin_passkey_settings',
            'mdlogin_passkey_general',
            array('field' => 'require_https')
        );

        add_settings_field(
            'session_timeout',
            __('Session Timeout (seconds)', 'multidots-passkey-login'),
            array($this, 'mdlogin_number_field_callback'),
            'mdlogin_passkey_settings',
            'mdlogin_passkey_general',
            array('field' => 'session_timeout', 'min' => 60, 'max' => 3600)
        );

        add_settings_field(
            'max_credentials_per_user',
            __('Max Credentials per User', 'multidots-passkey-login'),
            array($this, 'mdlogin_number_field_callback'),
            'mdlogin_passkey_settings',
            'mdlogin_passkey_general',
            array('field' => 'max_credentials_per_user', 'min' => 1, 'max' => 10)
        );
    }

    /**
     * Sanitize settings
     *
     * @param array $input Input data
     * @return array
     */
    public function mdlogin_sanitize_settings($input) {
        $sanitized = array();

        $sanitized['enabled'] = isset($input['enabled']) ? true : false;
        $sanitized['require_https'] = isset($input['require_https']) ? true : false;
        $sanitized['session_timeout'] = absint($input['session_timeout'] ?? 300);
        $sanitized['max_credentials_per_user'] = absint($input['max_credentials_per_user'] ?? 3);


        // Validate ranges
        if ($sanitized['session_timeout'] < 60) {
            $sanitized['session_timeout'] = 60;
        } elseif ($sanitized['session_timeout'] > 3600) {
            $sanitized['session_timeout'] = 3600;
        }

        if ($sanitized['max_credentials_per_user'] < 1) {
            $sanitized['max_credentials_per_user'] = 1;
        } elseif ($sanitized['max_credentials_per_user'] > 10) {
            $sanitized['max_credentials_per_user'] = 10;
        }

        return $sanitized;
    }

    /**
     * Settings section callback
     */
    public function mdlogin_settings_section_callback() {
        echo '<p>' . esc_html__('Configure the Passkey plugin settings.', 'multidots-passkey-login') . '</p>';
    }

    /**
     * Checkbox field callback
     *
     * @param array $args Field arguments
     */
    public function mdlogin_checkbox_field_callback($args) {
        $settings = get_option('mdlogin_passkey_settings', array());
        $field = $args['field'];
        $value = isset($settings[$field]) ? $settings[$field] : false;
        
        echo '<input type="checkbox" id="' . esc_attr($field) . '" name="mdlogin_passkey_settings[' . esc_attr($field) . ']" value="1" ' . checked(1, $value, false) . '>';
        echo '<label for="' . esc_attr($field) . '">' . esc_html__('Enable', 'multidots-passkey-login') . '</label>';
        
    }

    /**
     * Number field callback
     *
     * @param array $args Field arguments
     */
    public function mdlogin_number_field_callback($args) {
        $settings = get_option('mdlogin_passkey_settings', array());
        $field = $args['field'];
        $value = isset($settings[$field]) ? $settings[$field] : $args['min'] ?? 0;
        $min = $args['min'] ?? 0;
        $max = $args['max'] ?? 999;
        
        echo '<input type="number" id="' . esc_attr($field) . '" name="mdlogin_passkey_settings[' . esc_attr($field) . ']" value="' . esc_attr($value) . '" min="' . esc_attr($min) . '" max="' . esc_attr($max) . '">';
    }

    /**
     * Add settings link to plugins page
     *
     * @param array $links Plugin action links
     * @return array
     */
    public function mdlogin_add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=mdlogin-settings') . '">' . esc_html__('Settings', 'multidots-passkey-login') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Admin page callback
     */
    public function mdlogin_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'multidots-passkey-login'));
        }

        // Load the list table
        require_once MDLOGIN_PASSKEY_PLUGIN_DIR . 'admin/class-mdlogin-passkey-users-list-table.php';
        $list_table = new MDLOGIN_Passkey_Users_List_Table();
        
        // Process bulk actions
        $list_table->process_bulk_action();
        
        $list_table->prepare_items();
        
        ?>
        <div class="mdlogin-wrap mdlogin-management">
            <div id="mdlogin-header" class="mdlogin-header" style="">
                <div class="mdlogin-header__left">
                    <h1 class="mdlogin-header_title"><?php esc_html_e('Active Passkey Users', 'multidots-passkey-login'); ?></h1>
                </div>
                <div class="mdlogin-header__right">
                    <a href="<?php echo esc_url('https://www.multidots.com/'); ?>" target="_blank" class="mdlogin-logo"> 
                        <img src="<?php echo esc_url(MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/images/MDLOGIN-Logo.svg'); ?>" width="130" height="75" class="mdlogin-header__logo" alt="md logo"> 
                    </a>
                </div>
            </div>
            
            <div class="mdlogin-main-wrap">

                <div class="mdlogin-table-container">
                    <form method="post">
                        <?php
                        $list_table->search_box(__('Search', 'multidots-passkey-login'), 'user-search');
                        $list_table->display();
                        ?>
                    </form>
                </div>
            </div>
            
            <!-- Credentials Modal -->
            <div id="mdlogin-modal" class="mdlogin-modal" style="display: none;">
                <div class="mdlogin-modal-content">
                    <span class="mdlogin-modal-close">&times;</span>
                    <h2><?php esc_html_e('User Credentials', 'multidots-passkey-login'); ?></h2>
                    <div id="mdlogin-credentials-list"></div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Settings page callback
     */
    public function mdlogin_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'multidots-passkey-login'));
        }
        ?>
        <div class="mdlogin-wrap">
            <div id="mdlogin-header" class="mdlogin-header" style="">
                <div class="mdlogin-header__left">
                </div>
                <div class="mdlogin-header__right">
                    <a href="<?php echo esc_url('https://www.multidots.com/'); ?>" target="_blank" class="mdlogin-logo"> <img src="<?php echo esc_url( MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/images/MDLOGIN-Logo.svg');?>" width="130" height="75" class="mdlogin-header__logo" alt="md logo"> </a>
                </div>
            </div>
            <div class="mdlogin-main-wrap">
                  <?php
                    // Current active tab - validate against allowed values for security
                    $active_tab = 'settings'; // Default tab
                    $allowed_tabs = array( 'settings', 'shortcodes', 'system_info' );
                    
                    // Get tab parameter safely using WordPress functions
                    $requested_tab = filter_input( INPUT_GET, 'tab', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
                    if ( $requested_tab ) {
                        $requested_tab = sanitize_text_field( $requested_tab );
                    }
                    
                    // Validate tab value against whitelist
                    if ( ! empty( $requested_tab ) && in_array( $requested_tab, $allowed_tabs, true ) ) {
                        $active_tab = $requested_tab;
                    }
                    ?>

                    <!-- Tabs -->
                    <h2 class="nav-tab-wrapper">
                        <a href="?page=mdlogin-settings&tab=settings" class="nav-tab <?php echo esc_attr($active_tab === 'settings' ? 'nav-tab-active' : ''); ?>">
                            <?php esc_html_e( 'Settings', 'multidots-passkey-login' ); ?>
                        </a>
                        <a href="?page=mdlogin-settings&tab=shortcodes" class="nav-tab <?php echo esc_attr($active_tab === 'shortcodes' ? 'nav-tab-active' : ''); ?>">
                            <?php esc_html_e( 'Shortcodes', 'multidots-passkey-login' ); ?>
                        </a>
                        <a href="?page=mdlogin-settings&tab=system_info" class="nav-tab <?php echo esc_attr($active_tab === 'system_info' ? 'nav-tab-active' : ''); ?>">
                            <?php esc_html_e( 'System Info', 'multidots-passkey-login' ); ?>
                        </a>
                    </h2>
                    <div class="tab-content">
                        <?php if ( $active_tab === 'settings' ) : ?>
                            
                            <!-- Tab 1: Settings Form -->
                            <form method="post" action="options.php">
                                <?php
                                settings_fields('mdlogin_passkey_settings');
                                do_settings_sections('mdlogin_passkey_settings');
                                submit_button();
                                ?>
                            </form>

                        <?php elseif ( $active_tab === 'shortcodes' ) : ?>

                            <!-- Tab 2: Shortcodes Section -->
                            <div class="mdlogin-shortcodes-section">
                                <h2><?php esc_html_e('Available Shortcodes', 'multidots-passkey-login'); ?></h2>
                                <p><?php esc_html_e('Use these shortcodes to add passkey functionality to your pages and posts:', 'multidots-passkey-login'); ?></p>
                                
                                <?php
                                $shortcodes = MDLOGIN_Passkey_Shortcodes::mdlogin_get_available_shortcodes();
                                foreach ($shortcodes as $key => $shortcode):
                                ?>
                                <div class="mdlogin-shortcode-item">
                                    <h3><?php echo esc_html(ucfirst($key)); ?> Shortcode</h3>
                                    <div class="mdlogin-shortcode-code">
                                        <code><?php echo esc_html($shortcode['shortcode']); ?></code>
                                    </div>
                                    <p><?php echo esc_html($shortcode['description']); ?></p>
                                </div>
                                <?php endforeach; ?>
                            </div>

                        <?php elseif ( $active_tab === 'system_info' ) : ?>

                            <!-- Tab 3: System Info -->
                            <div class="mdlogin-settings-info">
                                <h2><?php esc_html_e('System Information', 'multidots-passkey-login'); ?></h2>
                                <table class="form-table">
                                    <tr>
                                        <th><?php esc_html_e('PHP Version', 'multidots-passkey-login'); ?></th>
                                        <td><?php echo esc_html(PHP_VERSION); ?></td>
                                    </tr>
                                    <tr>
                                        <th><?php esc_html_e('WordPress Version', 'multidots-passkey-login'); ?></th>
                                        <td><?php echo esc_html(get_bloginfo('version')); ?></td>
                                    </tr>
                                    <tr>
                                        <th><?php esc_html_e('HTTPS Enabled', 'multidots-passkey-login'); ?></th>
                                        <td><?php echo is_ssl() ? '✓' : '✗'; ?></td>
                                    </tr>
                                    <tr>
                                        <th><?php esc_html_e('WebAuthn Support', 'multidots-passkey-login'); ?></th>
                                        <td><?php echo esc_html($this->mdlogin_check_webauthn_support() ? '✓' : '✗'); ?></td>
                                    </tr>
                                </table>
                            </div>

                        <?php endif; ?>
                    </div>
            </div> 
            <div class="mdlogin-footer">
                <a href="<?php echo esc_url('https://www.multidots.com/contact-us/'); ?>" target="_blank">
                    <img src="<?php echo esc_url( MDLOGIN_PASSKEY_PLUGIN_URL . 'assets/images/footer-banner.png');?>" alt="Multidots Banner"/>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * AJAX handler for getting user credentials
     */
    public function mdlogin_ajax_get_user_credentials() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_admin_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }


        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions.', 'multidots-passkey-login')));
        }

        $user_id = intval($_POST['user_id'] ?? 0);
        if (!$user_id) {
            wp_send_json_error(array('message' => __('Invalid user ID.', 'multidots-passkey-login')));
        }

        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_send_json_error(array('message' => __('User not found.', 'multidots-passkey-login')));
        }

        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials_for_display($user_id);

        wp_send_json_success(array(
            'user' => array(
                'id' => $user->ID,
                'name' => $user->display_name,
                'login' => $user->user_login
            ),
            'credentials' => $user_credentials
        ));
    }

    /**
     * AJAX handler for deleting credential
     */
    public function mdlogin_ajax_delete_credential() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_admin_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }


        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions.', 'multidots-passkey-login')));
        }

        $user_id = intval($_POST['user_id'] ?? 0);
        $credential_id = isset( $_POST['credential_id'] )
            ? sanitize_text_field( wp_unslash( $_POST['credential_id'] ) )
            : '';
        
        if (!$user_id || !$credential_id) {
            wp_send_json_error(array('message' => __('Invalid parameters.', 'multidots-passkey-login')));
        }

        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_send_json_error(array('message' => __('User not found.', 'multidots-passkey-login')));
        }

        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials($user_id);
        
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
     * AJAX handler for deleting all credentials for a user
     */
    public function mdlogin_ajax_delete_all_credentials() {
        // Verify nonce
        if (
            ! wp_verify_nonce(
                sanitize_text_field( wp_unslash( $_POST['nonce'] ?? '' ) ),
                'mdlogin_passkey_admin_nonce'
            )
        ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Security check failed.', 'multidots-passkey-login' ),
                )
            );
        }


        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Insufficient permissions.', 'multidots-passkey-login')));
        }

        $user_id = intval($_POST['user_id'] ?? 0);
        
        if (!$user_id) {
            wp_send_json_error(array('message' => __('Invalid user ID.', 'multidots-passkey-login')));
        }

        $user = get_user_by('ID', $user_id);
        if (!$user) {
            wp_send_json_error(array('message' => __('User not found.', 'multidots-passkey-login')));
        }

        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $user_credentials = $credentials->mdlogin_get_user_credentials($user_id);
        
        if (empty($user_credentials)) {
            wp_send_json_error(array('message' => __('No credentials found for this user.', 'multidots-passkey-login')));
        }

        // Delete all credentials
        $deleted_count = 0;
        foreach ($user_credentials as $credential) {
            if ($credential instanceof \Webauthn\PublicKeyCredentialSource) {
                $credentials->deleteCredentialSource($credential);
                $deleted_count++;
            }
        }

        if ($deleted_count > 0) {
            wp_send_json_success(array(
                'message' => sprintf(
                    /* translators: %d: Number of credentials deleted */
                    __('%d credentials deleted successfully.', 'multidots-passkey-login'),
                    $deleted_count
                )
            ));
        } else {
            wp_send_json_error(array('message' => __('No credentials were deleted.', 'multidots-passkey-login')));
        }
    }

    // Bulk actions are now handled by WordPress's native list table system

    /**
     * Check WebAuthn support
     *
     * @return bool
     */
    private function mdlogin_check_webauthn_support() {
        // Check if required extensions are available
        $required_extensions = array('openssl', 'json', 'mbstring');
        foreach ($required_extensions as $extension) {
            if (!extension_loaded($extension)) {
                return false;
            }
        }

        // Check if Composer dependencies are available
        if (!class_exists('Webauthn\Server')) {
            return false;
        }

        return true;
    }
} 