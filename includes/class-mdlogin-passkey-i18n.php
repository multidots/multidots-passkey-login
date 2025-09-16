<?php
/**
 * Internationalization (i18n) Class
 *
 * Handles text domain reference for the Passkey plugin
 *
 * @package MDLOGIN_Passkey
 * @since 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * MDLOGIN_Passkey_I18n class
 *
 * @since 1.0.0
 */
class MDLOGIN_Passkey_I18n {

    /**
     * Instance of this class
     *
     * @var MDLOGIN_Passkey_I18n
     */
    private static $instance = null;

    /**
     * Text domain for the plugin
     *
     * @var string
     */
    private $text_domain = 'multidots-passkey-login';

    /**
     * Get instance of this class
     *
     * @return MDLOGIN_Passkey_I18n
     */
    public static function mdlogin_get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Get text domain
     *
     * @return string
     */
    public function mdlogin_get_text_domain() {
        return $this->text_domain;
    }

    /**
     * Check if text domain is loaded
     *
     * @return bool
     */
    public function mdlogin_is_textdomain_loaded() {
        return is_textdomain_loaded( $this->text_domain );
    }
}
