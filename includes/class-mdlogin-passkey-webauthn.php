<?php
/**
 * WebAuthn Server Class
 * 
 * Handles WebAuthn operations and credential management for Framework 4.9.x
 * 
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

use Cose\Algorithm\Manager as CoseAlgorithmManager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Laminas\Diactoros\ServerRequestFactory;
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialDescriptorCollection;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

/**
 * MDLOGIN_Passkey_WebAuthn class
 * 
 * @since 1.0.0
 */
class MDLOGIN_Passkey_WebAuthn {

    private static ?MDLOGIN_Passkey_WebAuthn $instance = null;

    private MDLOGIN_Passkey_Credentials $credential_repository;
    private PublicKeyCredentialLoader $credential_loader;
    private AuthenticatorAttestationResponseValidator $attestation_validator;
    private AuthenticatorAssertionResponseValidator $assertion_validator;

    public static function mdlogin_get_instance(): MDLOGIN_Passkey_WebAuthn {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->mdlogin_init_webauthn_components();
    }

    private function mdlogin_init_webauthn_components(): void {
        $this->credential_repository = MDLOGIN_Passkey_Credentials::mdlogin_get_instance();

        // Algorithm manager (add more algorithms if needed)
        $algorithmManager = CoseAlgorithmManager::create([
            new ES256(),
        ]);

        // Attestation statement support manager
        $attestationStatementSupportManager = new AttestationStatementSupportManager();

        // Credential loader
        $this->credential_loader = new PublicKeyCredentialLoader(
            new AttestationObjectLoader(
                $attestationStatementSupportManager
            )
        );

        // Validators
        $tokenBindingHandler = new TokenBindingNotSupportedHandler();

        $this->attestation_validator = new AuthenticatorAttestationResponseValidator(
            $attestationStatementSupportManager,
            $this->credential_repository,
            $tokenBindingHandler
        );

        $this->assertion_validator = new AuthenticatorAssertionResponseValidator(
            $this->credential_repository,
            $tokenBindingHandler
        );
    }

    public function mdlogin_generate_creation_options(PublicKeyCredentialUserEntity $user_entity): PublicKeyCredentialCreationOptions {
        try {
            $exclude_credentials = $this->credential_repository->findAllForUserEntity($user_entity);

            $exclude_descriptors = new PublicKeyCredentialDescriptorCollection();
            foreach ($exclude_credentials as $credential) {
                if ($credential instanceof PublicKeyCredentialSource) {
                    $exclude_descriptors->add(new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                        $credential->getPublicKeyCredentialId(),
                        $credential->getTransports()
                    ));
                }
            }

            // Get the current domain properly for WebAuthn
            $current_domain = $this->mdlogin_get_current_domain();
            $current_domain = $this->mdlogin_sanitize_domain($current_domain);

            $rp_entity = new PublicKeyCredentialRpEntity(
                get_bloginfo('name'),
                $current_domain
            );

            // Create creation options with required parameters
            $creation_options = PublicKeyCredentialCreationOptions::create(
                $rp_entity,
                $user_entity,
                random_bytes(32), // challenge
                [new PublicKeyCredentialParameters('public-key', -7)] // ES256 algorithm
            );

            // Set additional properties
            if ($exclude_descriptors->count() > 0) {
                // In WebAuthn 4.x, excludeCredentials expects individual descriptors, not a collection
                if (method_exists($creation_options, 'setExcludeCredentials')) {
                    $creation_options->setExcludeCredentials($exclude_descriptors);
                } elseif (method_exists($creation_options, 'excludeCredentials')) {
                    // Add each descriptor individually
                    foreach ($exclude_descriptors as $descriptor) {
                        $creation_options->excludeCredentials($descriptor);
                    }
                } elseif (method_exists($creation_options, 'withExcludeCredentials')) {
                    // Add each descriptor individually
                    foreach ($exclude_descriptors as $descriptor) {
                        $creation_options = $creation_options->withExcludeCredentials($descriptor);
                    }
                }
            }

            // Create authenticator selection criteria
            $authenticator_selection = AuthenticatorSelectionCriteria::create()
                ->setUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);

            // Set additional properties using the correct methods
            // Note: Attestation preference is set during creation in WebAuthn 4.9.x
            $creation_options->setAuthenticatorSelection($authenticator_selection);
            $creation_options->setTimeout(60000);

            return $creation_options;
        } catch (Exception $e) {
            throw $e;
        } catch (Error $e) {
            throw $e;
        }
    }

    public function mdlogin_generate_request_options(?array $allowed_credentials = null): PublicKeyCredentialRequestOptions {
        $allow_descriptors = new PublicKeyCredentialDescriptorCollection();

        if ($allowed_credentials) {
            foreach ($allowed_credentials as $index => $credential) {
                if ($credential instanceof PublicKeyCredentialSource) {
                    $credential_id = $credential->getPublicKeyCredentialId();
                    $credential_id_hex = bin2hex($credential_id);
                    $credential_id_b64 = base64_encode($credential_id);

                    $allow_descriptors->add(new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                        $credential_id,
                        $credential->getTransports()
                    ));
                }
            }
        }

        // Get the current domain properly for WebAuthn
        $current_domain = $this->mdlogin_get_current_domain();
        $current_domain = $this->mdlogin_sanitize_domain($current_domain);
        // Create request options with required parameters
        $challenge = random_bytes(32);
        $request_options = PublicKeyCredentialRequestOptions::create($challenge);
        
        // Set rpId (relying party ID)
        if (method_exists($request_options, 'setRpId')) {
            $request_options->setRpId($current_domain);
        } elseif (method_exists($request_options, 'rpId')) {
            $request_options->rpId($current_domain);
        } elseif (method_exists($request_options, 'withRpId')) {
            $request_options = $request_options->withRpId($current_domain);
        }
        
        // Set additional properties using the correct methods
        $request_options->setUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);
        $request_options->setTimeout(60000);
        
        // Set allowCredentials if we have any
        if ($allow_descriptors->count() > 0) {
            // Try different method names that might exist in WebAuthn 4.9.x
            if (method_exists($request_options, 'setAllowCredentials')) {
                $request_options->setAllowCredentials($allow_descriptors);
            } elseif (method_exists($request_options, 'allowCredentials')) {
                // The allowCredentials method expects individual descriptors, not a collection
                // We need to add them one by one
                foreach ($allow_descriptors as $descriptor) {
                    $request_options->allowCredentials($descriptor);
                }
            } elseif (method_exists($request_options, 'withAllowCredentials')) {
                // The withAllowCredentials method also expects individual descriptors
                foreach ($allow_descriptors as $descriptor) {
                    $request_options = $request_options->withAllowCredentials($descriptor);
                }
            }
            
            // Verify that allowCredentials were set
            if (method_exists($request_options, 'getAllowCredentials')) {
                $set_creds = $request_options->getAllowCredentials();
            }
        }
        return $request_options;
    }

    /**
     * Get the current domain for WebAuthn operations
     *
     * @return string
     */
    private function mdlogin_get_current_domain(): string {
        // Try to get from HTTP_HOST first (most reliable for current request)
        if (isset($_SERVER['HTTP_HOST'])) {
            $host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
            // Remove port if present
            if (strpos($host, ':') !== false) {
                $host = explode(':', $host)[0];
            }
            
            // Clean and validate the host
            $host = trim($host);
            if (!empty($host) && $host !== 'localhost') {
                // Additional validation for HTTP_HOST
                if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $host)) {
                    return $host;
                }
            }
        }

        // Fallback to WordPress site URL
        $site_url = get_site_url();
        $parsed = wp_parse_url($site_url);
        $host = $parsed['host'] ?? '';
        
        // Clean the host
        $host = trim($host);

        // Handle localhost and local development
        if (empty($host) || $host === 'localhost' || strpos($host, '.local') !== false || strpos($host, '.test') !== false) {
            return 'localhost';
        }

        // Additional validation - ensure we have a valid domain
        if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return $host;
        }

        return 'localhost';
    }

    /**
     * Sanitize and validate domain for WebAuthn operations
     *
     * @param string $domain
     * @return string
     */
    private function mdlogin_sanitize_domain(string $domain): string {
        // Remove any non-printable characters
        $domain = preg_replace('/[^\x20-\x7E]/', '', $domain);
        
        // Remove any invalid characters
        $domain = preg_replace('/[^a-zA-Z0-9\-\.]/', '', $domain);
        
        // Ensure it starts and ends with alphanumeric
        $domain = trim($domain, '.-');
        
        // Validate the final domain
        if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return $domain;
        }
        
        // If still invalid, return localhost
        return 'localhost';
    }

    public function mdlogin_load_and_check_attestation_response(string $data, PublicKeyCredentialCreationOptions $creation_options, ?ServerRequestInterface $server_request = null): PublicKeyCredentialSource {
        $server_request ??= $this->mdlogin_create_server_request();

        $public_key_credential = $this->credential_loader->load($data);

        // Extract the attestation response from the public key credential
        if (!$public_key_credential->getResponse() instanceof \Webauthn\AuthenticatorAttestationResponse) {
            throw new \InvalidArgumentException('Invalid attestation response type');
        }

        $attestation_response = $public_key_credential->getResponse();

        return $this->attestation_validator->check(
            $attestation_response,
            $creation_options,
            $server_request
        );
    }

    public function mdlogin_load_and_check_assertion_response(string $data, PublicKeyCredentialRequestOptions $request_options, ?PublicKeyCredentialUserEntity $user_entity = null, ?ServerRequestInterface $server_request = null): PublicKeyCredentialSource {
        $server_request ??= $this->mdlogin_create_server_request();

        $public_key_credential = $this->credential_loader->load($data);

        // Extract the assertion response from the public key credential
        if (!$public_key_credential->getResponse() instanceof \Webauthn\AuthenticatorAssertionResponse) {
            throw new \InvalidArgumentException('Invalid assertion response type');
        }

        $assertion_response = $public_key_credential->getResponse();

        // For assertion validation, we need to find the credential source first
        // The validator needs the credential ID to look up the stored credential
        $credential_id = $public_key_credential->getId();
        
        
        // The credential ID from the browser is in base64url format
        // We need to convert it to standard base64 for lookup
        if (is_string($credential_id)) {
            // Convert base64url to standard base64
            $standard_base64 = str_replace(['-', '_'], ['+', '/'], $credential_id);
            
            // Add padding if needed
            switch (strlen($standard_base64) % 4) {
                case 2: $standard_base64 .= '=='; break;
                case 3: $standard_base64 .= '='; break;
            }
            
            // Decode to binary for lookup
            $binary_id = base64_decode($standard_base64);
            if ($binary_id !== false) {
                $credential_id = $binary_id;
            }
        }
        // Find the stored credential source
        $stored_credential = $this->credential_repository->findOneByCredentialId($credential_id);
        
        // Verify assertion response
        $credential_source = $this->assertion_validator->check(
            $stored_credential,  // First parameter: PublicKeyCredentialSource
            $assertion_response,  // Second parameter: AuthenticatorAssertionResponse
            $request_options,     // Third parameter: PublicKeyCredentialRequestOptions
            $server_request,      // Fourth parameter: ServerRequestInterface
            $user_entity         // Fifth parameter: PublicKeyCredentialUserEntity
        );
        return $credential_source;
    }

    private function mdlogin_create_server_request(): ServerRequestInterface {
        // Create a minimal ServerRequest for WebAuthn validation
        // We only need basic server information, not form data
        $server = array(
            'REQUEST_METHOD' => isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET',
            'REQUEST_URI' => isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/',
            'HTTP_HOST' => isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : 'localhost',
            'HTTPS' => isset($_SERVER['HTTPS']) ? sanitize_text_field(wp_unslash($_SERVER['HTTPS'])) : 'off',
            'SERVER_PORT' => isset($_SERVER['SERVER_PORT']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_PORT'])) : '80',
            'HTTP_USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '',
            'HTTP_ACCEPT' => isset($_SERVER['HTTP_ACCEPT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'])) : '*/*',
            'HTTP_ACCEPT_LANGUAGE' => isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'])) : '',
            'HTTP_ACCEPT_ENCODING' => isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'])) : '',
        );
        
        // Create empty arrays for GET, POST, COOKIE, FILES since we don't need them for WebAuthn validation
        return ServerRequestFactory::fromGlobals($server, array(), array(), array(), array());
    }

    public function mdlogin_get_credential_repository(): MDLOGIN_Passkey_Credentials {
        return $this->credential_repository;
    }

    public function mdlogin_create_user_entity(\WP_User $user): PublicKeyCredentialUserEntity {
        try {
            return new PublicKeyCredentialUserEntity(
                $user->user_login,
                (string) $user->ID,
                $user->display_name
            );
        } catch (Exception $e) {
            throw $e;
        } catch (Error $e) {
            throw $e;
        }
    }

    /**
     * Convert creation options to array for JSON serialization
     *
     * @param PublicKeyCredentialCreationOptions $options Creation options
     * @return array
     */
    public function mdlogin_creation_options_to_array($options) {
        try {
            $authenticator_selection = $options->getAuthenticatorSelection();
            $exclude_credentials = $options->getExcludeCredentials();
            
            // Safely extract authenticator selection data
            $authenticator_selection_data = null;
            if ($authenticator_selection) {
                try {
                    $authenticator_selection_data = array(
                        'attachment_mode' => null, // Default to null for cross-platform compatibility
                        'require_resident_key' => false, // Default to false for security
                        'user_verification' => 'preferred', // Default to preferred
                        'resident_key' => null // Default to null
                    );
                    
                    // Only try to get values if methods exist and don't throw errors
                    if (method_exists($authenticator_selection, 'getUserVerification')) {
                        $user_verification = $authenticator_selection->getUserVerification();
                        if ($user_verification !== null) {
                            $authenticator_selection_data['user_verification'] = $user_verification;
                        }
                    }
                } catch (Exception $e) {
                    $authenticator_selection_data = array(
                        'attachment_mode' => null,
                        'require_resident_key' => false,
                        'user_verification' => 'preferred',
                        'resident_key' => null
                    );
                }
            }
            
            return array(
                'publicKey' => array(
                    'rp' => array(
                        'name' => $options->getRp()->getName(),
                        'id' => $options->getRp()->getId()
                    ),
                    'user' => array(
                        'id' => base64_encode($options->getUser()->getId()),
                        'name' => $options->getUser()->getName(),
                        'displayName' => $options->getUser()->getDisplayName()
                    ),
                    'challenge' => base64_encode($options->getChallenge()),
                    'pubKeyCredParams' => $options->getPubKeyCredParams(),
                    'timeout' => $options->getTimeout(),
                    'excludeCredentials' => $exclude_credentials ? array_map(function($credential) {
                        return array(
                            'type' => $credential->getType(),
                            'id' => base64_encode($credential->getId()),
                            'transports' => $credential->getTransports()
                        );
                    }, $exclude_credentials) : [],
                    'authenticatorSelection' => $authenticator_selection_data,
                    'attestation' => $options->getAttestation()
                )
            );
        } catch (Exception $e) {
            throw $e;
        } catch (Error $e) {
            throw $e;
        }
    }

    /**
     * Recreate creation options from stored data
     *
     * @param array $options_data Stored options data
     * @param string $challenge Challenge data (raw binary)
     * @return PublicKeyCredentialCreationOptions
     */
    public function mdlogin_recreate_creation_options($options_data, $challenge) {
        try {
            // Recreate relying party entity
            $rp_entity = new PublicKeyCredentialRpEntity(
                $options_data['rp_name'],
                $options_data['rp_id']
            );

            // Recreate user entity
            $user_entity = new PublicKeyCredentialUserEntity(
                $options_data['user_name'],
                $options_data['user_id'],
                $options_data['user_display_name']
            );
            
            // Convert pub_key_cred_params back to objects
            $pub_key_cred_params = array();
            foreach ($options_data['pub_key_cred_params'] as $param_data) {
                $pub_key_cred_params[] = new PublicKeyCredentialParameters(
                    $param_data['type'],
                    $param_data['alg']
                );
            }
            
            // Create creation options using the factory
            $creation_options = PublicKeyCredentialCreationOptions::create(
                $rp_entity,
                $user_entity,
                $challenge,
                $pub_key_cred_params
            );
            
            // Set additional properties
            if (isset($options_data['timeout'])) {
                $creation_options->setTimeout($options_data['timeout']);
            }
            
            if (isset($options_data['exclude_credentials']) && !empty($options_data['exclude_credentials'])) {
                $exclude_descriptors = new PublicKeyCredentialDescriptorCollection();
                foreach ($options_data['exclude_credentials'] as $credential_data) {
                    $exclude_descriptors->add(new PublicKeyCredentialDescriptor(
                        $credential_data['type'],
                        base64_decode($credential_data['id']),
                        $credential_data['transports'] ?? []
                    ));
                }
                // Try different method names that might exist in WebAuthn 4.9.x
                if (method_exists($creation_options, 'setExcludeCredentials')) {
                    $creation_options->setExcludeCredentials($exclude_descriptors);
                } elseif (method_exists($creation_options, 'excludeCredentials')) {
                    // Add each descriptor individually
                    foreach ($exclude_descriptors as $descriptor) {
                        $creation_options->excludeCredentials($descriptor);
                    }
                } elseif (method_exists($creation_options, 'withExcludeCredentials')) {
                    // Add each descriptor individually
                    foreach ($exclude_descriptors as $descriptor) {
                        $creation_options = $creation_options->withExcludeCredentials($descriptor);
                    }
                }
            }
            
            if (isset($options_data['authenticator_selection_data'])) {
                $auth_selection_data = $options_data['authenticator_selection_data'];
                $authenticator_selection = AuthenticatorSelectionCriteria::create()
                    ->setUserVerification(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED);
                $creation_options->setAuthenticatorSelection($authenticator_selection);
            }
            
            if (isset($options_data['attestation'])) {
                $creation_options->setAttestation($options_data['attestation']);
            }

            return $creation_options;
        } catch (Exception $e) {
            throw $e;
        } catch (Error $e) {
            throw $e;
        }
    }

    /**
     * Recreate request options from session data
     *
     * @param string $challenge Challenge string
     * @param array $allow_credentials Array of credential descriptors
     * @return PublicKeyCredentialRequestOptions|null
     */
    public function mdlogin_recreate_request_options(string $challenge, array $allow_credentials = []): ?PublicKeyCredentialRequestOptions {
        try {
            $current_domain = $this->mdlogin_get_current_domain();
            $current_domain = $this->mdlogin_sanitize_domain($current_domain);
            
            // Create base request options
            $request_options = PublicKeyCredentialRequestOptions::create($challenge);
            
            // Set rpId
            if (method_exists($request_options, 'setRpId')) {
                $request_options->setRpId($current_domain);
            } elseif (method_exists($request_options, 'rpId')) {
                $request_options->rpId($current_domain);
            } elseif (method_exists($request_options, 'withRpId')) {
                $request_options = $request_options->withRpId($current_domain);
            }
            // Set timeout
            $request_options->setTimeout(60000);
            
            // Set user verification
            $request_options->setUserVerification('preferred');
            
            // Set allowCredentials if provided
            if (!empty($allow_credentials)) {
                $credential_descriptors = new \Webauthn\PublicKeyCredentialDescriptorCollection();
                
                foreach ($allow_credentials as $index => $credential_data) {
                    try {
                        
                        $credential_id = base64_decode($credential_data['id']);
                        $transports = $credential_data['transports'] ?? [];

                        $descriptor = new \Webauthn\PublicKeyCredentialDescriptor(
                            $credential_data['type'],
                            $credential_id,
                            $transports
                        );
                        
                        $credential_descriptors->add($descriptor);
                    } catch (Exception $e) {
                        continue;
                    }
                }
                // Try different method names that might exist in WebAuthn 4.9.x
                if (method_exists($request_options, 'setAllowCredentials')) {
                    $request_options->setAllowCredentials($credential_descriptors);
                } elseif (method_exists($request_options, 'allowCredentials')) {
                    // The allowCredentials method expects individual descriptors, not a collection
                    foreach ($credential_descriptors as $descriptor) {
                        $request_options->allowCredentials($descriptor);
                    }
                } elseif (method_exists($request_options, 'withAllowCredentials')) {
                    // The withAllowCredentials method also expects individual descriptors
                    foreach ($credential_descriptors as $descriptor) {
                        $request_options = $request_options->withAllowCredentials($descriptor);
                    }
                }
            }
            return $request_options;
            
        } catch (Exception $e) {
            return null;
        } catch (Error $e) {
            return null;
        }
    }

    /**
     * Convert request options to array for JSON serialization
     *
     * @param PublicKeyCredentialRequestOptions $options Request options
     * @return array
     */
    public function mdlogin_request_options_to_array($options) {
        try {
            $allow_credentials = $options->getAllowCredentials();
            
            // Debug the rpId
            $rp_id = $options->getRpId();
            
            // The getRpId() method is returning corrupted data, so we'll use our clean domain
            $rp_id = $this->mdlogin_get_current_domain();
            
            return array(
                'publicKey' => array(
                    'challenge' => base64_encode($options->getChallenge()),
                    'timeout' => $options->getTimeout(),
                    'rpId' => $rp_id,
                    'allowCredentials' => $allow_credentials ? array_map(function($credential) {
                        return array(
                            'type' => $credential->getType(),
                            'id' => base64_encode($credential->getId()),
                            'transports' => $credential->getTransports()
                        );
                    }, $allow_credentials) : [],
                    'userVerification' => $options->getUserVerification()
                )
            );
        } catch (Exception $e) {
            throw $e;
        } catch (Error $e) {
            throw $e;
        }
    }
}