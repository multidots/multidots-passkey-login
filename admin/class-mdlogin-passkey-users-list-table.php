<?php
/**
 * Custom WordPress List Table for Passkey Users
 * 
 * Provides a proper WordPress admin table interface with search and filtering
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load WordPress list table class
if (!class_exists('WP_List_Table')) {
    require_once(ABSPATH . 'wp-admin/includes/class-wp-list-table.php');
}

/**
 * MDLOGIN_Passkey_Users_List_Table class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Users_List_Table extends WP_List_Table {

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct(array(
            'singular' => 'user',
            'plural'   => 'users',
            'ajax'     => false
        ));
    }

    /**
     * Get table columns
     *
     * @return array
     */
    public function get_columns() {
        return array(
            'cb' => '<input type="checkbox" />',
            'username' => __('Username', 'multidots-passkey-login'),
            'email' => __('Email', 'multidots-passkey-login'),
            'passkey_status' => __('Passkey Status', 'multidots-passkey-login'),
            'credential_id' => __('Credential ID', 'multidots-passkey-login'),
        );
    }

    /**
     * Get sortable columns
     *
     * @return array
     */
    public function get_sortable_columns() {
        return array(
            'username' => array('user_login', false),
            'email' => array('user_email', false),
            'passkey_status' => array('passkey_status', false),
            'credential_id' => array('credential_id', false),
        );
    }

    /**
     * Get bulk actions
     *
     * @return array
     */
    public function get_bulk_actions() {
        return array(
            'delete_credentials' => __('Delete Selected Credentials', 'multidots-passkey-login')
        );
    }

    /**
     * Process bulk actions
     */
    public function process_bulk_action() {
        $action = $this->current_action();
        
        if ($action === 'delete_credentials') {
            // Verify nonce for security
            $nonce = isset($_POST['_wpnonce']) ? sanitize_text_field(wp_unslash($_POST['_wpnonce'])) : '';
            if (empty($nonce) || !wp_verify_nonce($nonce, 'bulk-' . $this->_args['plural'])) {
                wp_die(esc_html__('Security check failed. Please try again.', 'multidots-passkey-login'));
            }
            
            // Check user capabilities
            if (!current_user_can('manage_options')) {
                wp_die(esc_html__('You do not have permission to perform this action.', 'multidots-passkey-login'));
            }
            
            // Sanitize and validate credentials data
            $selected_credentials = array();
            if (isset($_POST['credentials']) && is_array($_POST['credentials'])) {
                $selected_credentials = array_map('sanitize_text_field', wp_unslash($_POST['credentials']));
            }
            
            if ( ! is_array( $selected_credentials ) ) {
                $selected_credentials = array();
            }
            
            if (empty($selected_credentials)) {
                wp_die(esc_html__('No credentials selected.', 'multidots-passkey-login'));
            }

            $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
            $deleted_count = 0;
            $errors = array();

            foreach ($selected_credentials as $credential_data) {
                $parts = explode(':', $credential_data);
                if (count($parts) !== 2) {
                    $errors[] = 'Invalid credential format: ' . $credential_data;
                    continue;
                }

                $user_id = intval($parts[0]);
                $credential_id_url = $parts[1];

                $user = get_user_by('ID', $user_id);
                if (!$user) {
                    $errors[] = 'User not found for credential: ' . $credential_data;
                    continue;
                }

                $user_credentials = $credentials->mdlogin_get_user_credentials($user_id);
                
                foreach ($user_credentials as $credential) {
                    if ($credential instanceof \Webauthn\PublicKeyCredentialSource) {
                        $credential_id = base64_encode($credential->getPublicKeyCredentialId());
                        $current_credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id, '='));
                        
                        if ($current_credential_id_url === $credential_id_url) {
                            $credentials->deleteCredentialSource($credential);
                            $deleted_count++;
                            break;
                        }
                    }
                }
            }

            if ($deleted_count > 0) {
                $message = sprintf(
                    /* translators: %d: Number of credentials deleted */
                    __('%d credentials deleted successfully.', 'multidots-passkey-login'),
                    $deleted_count
                );
                if (!empty($errors)) {
                    $message .= ' ' . esc_html__('Some errors occurred:', 'multidots-passkey-login') . ' ' . implode(', ', $errors);
                }
                
                // Add admin notice
                add_action('admin_notices', function() use ($message) {
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($message) . '</p></div>';
                });
            } else {
                wp_die(esc_html__('No credentials were deleted.', 'multidots-passkey-login'));
            }
        }
    }

    /**
     * Column default
     *
     * @param array $item Credential row item
     * @param string $column_name Column name
     * @return string
     */
    public function column_default( $item, $column_name ) {
        switch ( $column_name ) {
            case 'email':
                $user = $item['user'];
                return esc_html( $user->user_email );

            default:
                return isset( $item[ $column_name ] )
                    ? esc_html( (string) $item[ $column_name ] )
                    : '';
        }
    }

    /**
     * Column username
     *
     * @param array $item Credential row item
     * @return string
     */
    public function column_username($item) {
        $user = $item['user'];
        return '<code>' . esc_html($user->user_login) . '</code>';
    }

    /**
     * Column passkey status
     *
     * @param array $item Credential row item
     * @return string
     */
    public function column_passkey_status($item) {
        return '<span class="mdlogin-status-active">✓ ' . esc_html__('Active', 'multidots-passkey-login') . '</span>';
    }

    /**
     * Column credential ID
     *
     * @param array $item Credential row item
     * @return string
     */
    public function column_credential_id($item) {
        $credential = $item['credential'];
        
        if ($credential instanceof \Webauthn\PublicKeyCredentialSource) {
            $credential_id = base64_encode($credential->getPublicKeyCredentialId());
            $credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id, '='));
            
            return '<code>' . esc_html(substr($credential_id_url, 0, 20)) . '...</code>';
        }
        
        return '<span class="no-credential-id">—</span>';
    }

    /**
     * Column checkbox
     *
     * @param array $item Credential row item
     * @return string
     */
    public function column_cb($item) {
        $user = $item['user'];
        $credential = $item['credential'];
        
        if ($credential instanceof \Webauthn\PublicKeyCredentialSource) {
            $credential_id = base64_encode($credential->getPublicKeyCredentialId());
            $credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id, '='));
            
            return '<input type="checkbox" name="credentials[]" value="' . esc_attr($user->ID . ':' . $credential_id_url) . '" />';
        }
        
        return '';
    }

    /**
     * Prepare items
     */
    public function prepare_items() {
        // Set column headers
        $this->_column_headers = array(
            $this->get_columns(),
            array(),
            $this->get_sortable_columns()
        );

        // Get search term
        $search_term = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Search term is for filtering only, no data modification
        // Get filter values
        $passkey_status_filter = isset( $_REQUEST['passkey_status'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['passkey_status'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Passkey status filter is for display only, no data modification
        $role_filter = isset( $_REQUEST['role'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['role'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Role filter is for display only, no data modification

        // Build query args
        $args = array(
            'orderby' => $this->get_orderby(),
            'order' => $this->get_order(),
            'number' => $this->get_items_per_page('users_per_page', 20),
            'paged' => $this->get_pagenum(),
            'search' => $search_term
        );

        // Add role filter
        if (!empty($role_filter)) {
            $args['role'] = $role_filter;
        }

        // Get all users first (without pagination)
        $all_users_args = array(
            'orderby' => $this->get_orderby(),
            'order' => $this->get_order()
        );

        // Add role filter
        if (!empty($role_filter)) {
            $all_users_args['role'] = $role_filter;
        }

        // Handle search with partial matching
        if (!empty($search_term)) {
            $all_users_args['search'] = '*' . $search_term . '*';
            $all_users_args['search_columns'] = array('user_login', 'user_email', 'display_name');
        }

        $all_users_query = new WP_User_Query($all_users_args);
        $all_users = $all_users_query->get_results();

        // If search term is provided, apply additional partial matching
        if (!empty($search_term)) {
            $all_users = $this->mdlogin_apply_partial_search($all_users, $search_term);
        }

        // Create separate rows for each credential
        $credentials = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();
        $credential_rows = array();
        
        foreach ($all_users as $user) {
            $user_credentials = $credentials->mdlogin_get_user_credentials($user->ID);
            if (!empty($user_credentials)) {
                // Create a row for each credential
                foreach ($user_credentials as $index => $credential) {
                    $credential_rows[] = array(
                        'user' => $user,
                        'credential' => $credential,
                        'credential_index' => $index
                    );
                }
            }
        }

        // Apply pagination to credential rows
        $per_page = $this->get_items_per_page('users_per_page', 20);
        $current_page = $this->get_pagenum();
        $offset = ($current_page - 1) * $per_page;
        
        $this->items = array_slice($credential_rows, $offset, $per_page);

        // If no items found, check if it's a pagination issue
        if (empty($this->items) && count($credential_rows) > 0) {
            // Reset to first page if current page is beyond available data
            if ($current_page > 1) {
                $this->items = array_slice($credential_rows, 0, $per_page);
            }
        }

        // Set pagination with credential rows count
        $this->set_pagination_args(array(
            'total_items' => count($credential_rows),
            'per_page' => $per_page,
            'total_pages' => ceil(count($credential_rows) / $per_page)
        ));


    }

    /**
     * Get orderby
     *
     * @return string
     */
    private function get_orderby() {
       $orderby = isset( $_REQUEST['orderby'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['orderby'] ) ) : 'display_name'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Orderby is for sorting only, no data modification
        
        // Map custom columns to user fields
        $orderby_map = array(
            'user' => 'display_name',
            'username' => 'user_login',
            'email' => 'user_email',
            'passkey_status' => 'display_name', // Default to display_name for passkey status
            'credentials_count' => 'display_name', // Default to display_name for credentials count
            'last_login' => 'display_name' // Default to display_name for last login
        );
        
        return $orderby_map[$orderby] ?? 'display_name';
    }

    /**
     * Get order
     *
     * @return string
     */
    private function get_order() {
        return strtoupper( 
            isset( $_REQUEST['order'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) : 'ASC' // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Sorting only, no data modification
        ); 
    }

    /**
     * Get items per page
     *
     * @param string $option Option name
     * @param int $default Default value
     * @return int
     */
    public function get_items_per_page($option, $default = 20) {
        $per_page = (int) get_user_option($option);
        if (empty($per_page) || $per_page < 1) {
            $per_page = $default;
        }
        return $per_page;
    }

    /**
     * Apply partial search to user results
     *
     * @param array $users Array of user objects
     * @param string $search_term Search term
     * @return array Filtered users
     */
    private function mdlogin_apply_partial_search($users, $search_term) {
        $search_term = strtolower(trim($search_term));
        $filtered_users = array();

        foreach ($users as $user) {
            $username = strtolower($user->user_login);
            $email = strtolower($user->user_email);
            $display_name = strtolower($user->display_name);
            $first_name = strtolower($user->first_name);
            $last_name = strtolower($user->last_name);

            // Check if search term matches any part of the user data
            if (strpos($username, $search_term) !== false ||
                strpos($email, $search_term) !== false ||
                strpos($display_name, $search_term) !== false ||
                strpos($first_name, $search_term) !== false ||
                strpos($last_name, $search_term) !== false) {
                $filtered_users[] = $user;
            }
        }

        return $filtered_users;
    }

    /**
     * Apply partial search to credential rows
     *
     * @param array $credential_rows Array of credential row items
     * @param string $search_term Search term
     * @return array Filtered credential rows
     */
    private function mdlogin_apply_partial_search_credentials($credential_rows, $search_term) {
        $search_term = strtolower(trim($search_term));
        $filtered_rows = array();

        foreach ($credential_rows as $row) {
            $user = $row['user'];
            $username = strtolower($user->user_login);
            $email = strtolower($user->user_email);
            $display_name = strtolower($user->display_name);

            // Check if search term matches any part of the user data
            if (strpos($username, $search_term) !== false ||
                strpos($email, $search_term) !== false ||
                strpos($display_name, $search_term) !== false) {
                $filtered_rows[] = $row;
            }
        }

        return $filtered_rows;
    }

    /**
     * Detect authenticator from credential source
     *
     * @param PublicKeyCredentialSource $credential_source Credential source
     * @return array Authenticator information
     */
    private function mdlogin_detect_authenticator_from_credential($credential_source) {
        $aaguid = $credential_source->getAaguid();
        $aaguid_string = $aaguid ? $aaguid->toString() : '';
        
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
} 