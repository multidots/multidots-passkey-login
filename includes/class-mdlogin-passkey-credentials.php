<?php
/**
 * Credentials Class
 * 
 * Handles credential storage and management using WordPress user meta
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * MDLOGIN_Passkey_Credentials class
 * 
 * Implements WebAuthn credential repository interface
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_Credentials implements PublicKeyCredentialSourceRepository {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_Credentials
     */
    private static $instance = null;

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_Credentials
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
        // Constructor is private for singleton pattern
    }

    /**
     * Find credential by credential ID
     *
     * @param string $public_key_credential_id Credential ID (raw binary)
     * @return PublicKeyCredentialSource|null
     */
    public function findOneByCredentialId(string $public_key_credential_id): ?PublicKeyCredentialSource {
        $users = get_users();
        
        foreach ($users as $user) {
            $credentials = $this->mdlogin_get_user_credentials($user->ID);
            
            foreach ($credentials as $credential) {
                if ($credential instanceof PublicKeyCredentialSource) {
                    $stored_id = $credential->getPublicKeyCredentialId();
                    $stored_id_hex = bin2hex($stored_id);

                    if ($stored_id === $public_key_credential_id) {
                        return $credential;
                    } 
                }
            }
        }
        return null;
    }

    /**
     * Find all credentials for a user entity
     *
     * @param PublicKeyCredentialUserEntity $user_entity User entity
     * @return array
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $user_entity): array {
        $user_id = $this->mdlogin_get_user_id_from_user_entity($user_entity);
        if (!$user_id) {
            return array();
        }
        
        return $this->mdlogin_get_user_credentials($user_id);
    }

    /**
     * Save credential source
     *
     * @param PublicKeyCredentialSource $public_key_credential_source Credential source
     * @return void
     */
    public function saveCredentialSource(PublicKeyCredentialSource $public_key_credential_source, $authenticator_info = null): void {
        $user_handle = $public_key_credential_source->getUserHandle();
        $handle_hex = bin2hex($user_handle);

        
        // Try to find user by handle
        $user_id = $this->mdlogin_get_user_id_from_handle($user_handle);

        
        // If still not found, try to find by user ID from the handle
        if (!$user_id) {
            $user_id = hexdec($handle_hex);

            if (!$user_id || !get_user_by('ID', $user_id)) {
                // For registration, we need to get the user ID from the current session
                // This is a fallback for when the user handle doesn't match any existing user

                return;
            }
        }
        


        // Store the user handle mapping for future lookups
        $handle_hex = bin2hex($user_handle);
        update_user_meta($user_id, 'mdlogin_passkey_user_handle', $handle_hex);

        $existing = $this->mdlogin_get_user_credentials($user_id);
        
        // Check if credential already exists
        foreach ($existing as $stored) {
            if ($stored instanceof PublicKeyCredentialSource &&
                $stored->getPublicKeyCredentialId() === $public_key_credential_source->getPublicKeyCredentialId()) {
                return; // Already exists
            }
        }

        // Check if user has reached maximum credentials limit
        $settings = get_option('mdlogin_passkey_settings', array());
        $max_credentials = isset($settings['max_credentials_per_user']) ? $settings['max_credentials_per_user'] : 3;
        
        if (count($existing) >= $max_credentials) {
            return;
        }

        $existing[] = $public_key_credential_source;
        $this->mdlogin_save_user_credentials($user_id, $existing, $authenticator_info);
    }

    /**
     * Delete credential source
     *
     * @param PublicKeyCredentialSource $public_key_credential_source Credential source
     * @return void
     */
    public function deleteCredentialSource(PublicKeyCredentialSource $public_key_credential_source): void {
        $user_handle = $public_key_credential_source->getUserHandle();
        $user_id = $this->mdlogin_get_user_id_from_handle($user_handle);
        
        if (!$user_id) {
            return;
        }

        $existing = $this->mdlogin_get_user_credentials($user_id);
        $filtered = array_filter($existing, function($credential) use ($public_key_credential_source) {
            return !($credential instanceof PublicKeyCredentialSource &&
                $credential->getPublicKeyCredentialId() === $public_key_credential_source->getPublicKeyCredentialId());
        });

        $this->mdlogin_save_user_credentials($user_id, array_values($filtered));
    }

    /**
     * Get user credentials
     *
     * @param int $user_id User ID
     * @return array
     */
    public function mdlogin_get_user_credentials($user_id): array {
        $credentials_data = get_user_meta($user_id, 'mdlogin_passkey_credentials', true);
        if (!is_array($credentials_data)) {
            return array();
        }
        
        $credentials = array();
        foreach ($credentials_data as $index => $credential_data) {
            if (is_array($credential_data) && isset($credential_data['type']) && $credential_data['type'] === 'PublicKeyCredentialSource') {
                try {
                    $credential = $this->mdlogin_reconstruct_credential_source($credential_data);
                    if ($credential) {
                        $credentials[] = $credential;
                    }
                } catch (Exception $e) {
                    // Continue with other credentials
                } catch (Error $e) {
                    // Continue with other credentials
                }
            }
        }
        return $credentials;
    }

    /**
     * Save user credentials
     *
     * @param int $user_id User ID
     * @param array $credentials Credentials array
     * @return void
     */
    private function mdlogin_save_user_credentials($user_id, array $credentials, $authenticator_info = null): void {
        $credentials_data = array();
        foreach ($credentials as $index => $credential) {
            if ($credential instanceof PublicKeyCredentialSource) {
                // Add authenticator info only to the latest credential (last in array)
                $cred_authenticator_info = null;
                if ($authenticator_info && $index === count($credentials) - 1) {
                    $cred_authenticator_info = $authenticator_info;
                }
                
                $credentials_data[] = $this->mdlogin_serialize_credential_source($credential, $cred_authenticator_info);
            }
        }
        
        update_user_meta($user_id, 'mdlogin_passkey_credentials', $credentials_data);
    }

    /**
     * Serialize credential source for storage
     *
     * @param PublicKeyCredentialSource $credential Credential source
     * @param array $authenticator_info Optional authenticator information
     * @return array
     */
    private function mdlogin_serialize_credential_source(PublicKeyCredentialSource $credential, $authenticator_info = null): array {
        $data = array(
            'type' => 'PublicKeyCredentialSource',
            'publicKeyCredentialId' => base64_encode($credential->getPublicKeyCredentialId()),
            'credentialType' => $credential->getType(),
            'transports' => $credential->getTransports(),
            'attestationType' => $credential->getAttestationType(),
            'trustPath' => $credential->getTrustPath(),
            'aaguid' => $credential->getAaguid(),
            'credentialPublicKey' => base64_encode($credential->getCredentialPublicKey()),
            'userHandle' => base64_encode($credential->getUserHandle()),
            'counter' => $credential->getCounter(),
            'otherUI' => $credential->getOtherUI()
        );

        // Add authenticator information if provided
        if ($authenticator_info) {
            $data['authenticator_info'] = $authenticator_info;
        }

        return $data;
    }

    /**
     * Reconstruct credential source from stored data
     *
     * @param array $data Stored credential data
     * @return PublicKeyCredentialSource|null
     */
    private function mdlogin_reconstruct_credential_source(array $data): ?PublicKeyCredentialSource {
        try {
            return new PublicKeyCredentialSource(
                base64_decode($data['publicKeyCredentialId']),
                $data['credentialType'],
                $data['transports'],
                $data['attestationType'],
                $data['trustPath'],
                $data['aaguid'],
                base64_decode($data['credentialPublicKey']),
                base64_decode($data['userHandle']),
                $data['counter'],
                $data['otherUI'] ?? null
            );
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Get user ID from user entity
     *
     * @param PublicKeyCredentialUserEntity $user_entity User entity
     * @return int|null
     */
    private function mdlogin_get_user_id_from_user_entity(PublicKeyCredentialUserEntity $user_entity): ?int {
        $user = get_user_by('login', $user_entity->getName());
        return $user ? $user->ID : null;
    }

    /**
     * Get user ID from handle
     *
     * @param string $user_handle User handle
     * @return int|null
     */
    public function mdlogin_get_user_id_from_handle(string $user_handle): ?int {
        // Convert handle to hex for comparison
        $handle_hex = bin2hex($user_handle);
        
        // Try to find user by handle in user meta
        $users = get_users(array('meta_key' => 'mdlogin_passkey_user_handle', 'meta_value' => $handle_hex)); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value
        if (!empty($users)) {
            return $users[0]->ID;
        }
        
        // Try to find by user ID directly from the handle
        $handle_string = $user_handle;
        if (is_numeric($handle_string)) {
            $user_id = (int) $handle_string;
            if (get_user_by('ID', $user_id)) {
                return $user_id;
            }
        }
        
        // Fallback: try to find by username if handle matches user ID
        $user_id = hexdec($handle_hex);
        if ($user_id && get_user_by('ID', $user_id)) {
            return $user_id;
        }
        
        return null;
    }

    /**
     * Get user credentials for display (admin panel)
     *
     * @param int $user_id User ID
     * @return array
     */
    public function mdlogin_get_user_credentials_for_display($user_id): array {
        $credentials_data = get_user_meta($user_id, 'mdlogin_passkey_credentials', true);
        $display = array();
        
        if (!is_array($credentials_data)) {
            return $display;
        }
        
        foreach ($credentials_data as $credential_data) {
            if (is_array($credential_data) && isset($credential_data['type']) && $credential_data['type'] === 'PublicKeyCredentialSource') {
                $credential_id = $credential_data['publicKeyCredentialId'];
                $credential_id_url = str_replace(array('+', '/'), array('-', '_'), rtrim($credential_id, '='));
                
                // Get authenticator info if available
                $authenticator_name = 'Unknown Authenticator';
                if (isset($credential_data['authenticator_info']) && isset($credential_data['authenticator_info']['name'])) {
                    $authenticator_name = $credential_data['authenticator_info']['name'];
                }
                
                // Get creation date if available
                $created_at = current_time('mysql');
                if (isset($credential_data['created_at'])) {
                    $created_at = $credential_data['created_at'];
                }
                
                $credential_info = array(
                    'credential_id' => $credential_id_url,
                    'authenticator_name' => $authenticator_name,
                    'created_at' => $created_at,
                    'id' => $credential_id_url, // Keep for backward compatibility
                    'name' => isset($credential_data['userHandle']) ? bin2hex(base64_decode($credential_data['userHandle'])) : 'Unknown',
                    'created' => $credential_data['counter'] ?? 0,
                    'type' => $credential_data['credentialType'],
                    'transports' => $credential_data['transports'] ?? array()
                );
                
                
                $display[] = $credential_info;
            }
        }
        
        return $display;
    }

    /**
     * Get all users with passkey credentials
     *
     * @return array
     */
    public function mdlogin_get_users_with_credentials(): array {
        $users_with_credentials = array();
        $all_users = get_users(array('fields' => array('ID', 'user_login', 'display_name')));
        foreach ($all_users as $user) {
            $credentials = $this->mdlogin_get_user_credentials($user->ID);
            if (!empty($credentials)) {
                $users_with_credentials[] = array(
                    'id' => $user->ID,
                    'login' => $user->user_login,
                    'name' => $user->display_name,
                    'credentials' => $credentials
                );
            }
        }
        return $users_with_credentials;
    }

    /**
     * Check if user has credentials
     *
     * @param int $user_id User ID
     * @return bool
     */
    public function mdlogin_user_has_credentials($user_id): bool {
        $credentials = $this->mdlogin_get_user_credentials($user_id);
        return !empty($credentials);
    }

    /**
     * Get credential count for user
     *
     * @param int $user_id User ID
     * @return int
     */
    public function mdlogin_get_user_credential_count($user_id): int {
        $credentials = $this->mdlogin_get_user_credentials($user_id);
        return count($credentials);
    }

    /**
     * Check if user already has a credential from the same authenticator
     *
     * @param int $user_id User ID
     * @param string $authenticator_name Authenticator name to check
     * @return bool
     */
    public function mdlogin_user_has_authenticator($user_id, $authenticator_name): bool {
        $credentials_data = get_user_meta($user_id, 'mdlogin_passkey_credentials', true);
        
        if (!is_array($credentials_data)) {
            return false;
        }
        
        foreach ($credentials_data as $credential_data) {
            if (is_array($credential_data) && 
                isset($credential_data['authenticator_info']) && 
                isset($credential_data['authenticator_info']['name']) &&
                $credential_data['authenticator_info']['name'] === $authenticator_name) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Get list of authenticators used by user
     *
     * @param int $user_id User ID
     * @return array
     */
    public function mdlogin_get_user_authenticators($user_id): array {
        $credentials_data = get_user_meta($user_id, 'mdlogin_passkey_credentials', true);
        $authenticators = array();
        
        if (!is_array($credentials_data)) {
            return $authenticators;
        }
        
        foreach ($credentials_data as $credential_data) {
            if (is_array($credential_data) && 
                isset($credential_data['authenticator_info']) && 
                isset($credential_data['authenticator_info']['name'])) {
                $authenticators[] = $credential_data['authenticator_info']['name'];
            }
        }
        
        return array_unique($authenticators);
    }


} 