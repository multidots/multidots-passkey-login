# Passkey

A WordPress plugin that adds secure passkey authentication using WebAuthn to the WordPress login page. Users can register and login using their device's biometric authentication or PIN.

## Features

- **Secure Passkey Registration**: Users can register passkeys using their device's biometric authentication or PIN
- **Passkey**: Secure login using registered passkeys instead of passwords
- **Admin Management**: Admin panel to view and manage user passkey credentials
- **Settings Page**: Comprehensive settings for customization
- **Security Features**: Nonce verification, session management, rate limiting, and proper error handling
- **Modern UI**: Clean, user-friendly interface with status messages and feedback
- **Responsive Design**: Works on desktop and mobile devices
- **Accessibility**: WCAG compliant with proper focus management and screen reader support

## Requirements

- WordPress 6.0 or higher
- PHP 8.1 or higher
- HTTPS enabled (required for WebAuthn)
- Modern browser with WebAuthn support
- Device with biometric authentication or PIN capability

## Installation

### Method 1: Manual Installation

1. Download the plugin files
2. Upload the `multidots-passkey-login` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Run `composer install` in the plugin directory to install dependencies
5. Ensure your site is running on HTTPS (required for WebAuthn)

### Method 2: Composer Installation

```bash
cd wp-content/plugins
composer create-project passkey/wordpress-plugin multidots-passkey-login
cd multidots-passkey-login
composer install
```

Then activate the plugin through WordPress admin.

## Usage

### For Users

1. **Registering a Passkey** (for existing users):
   - Go to the WordPress login page (`/wp-login.php`)
   - Login to your WordPress account first
   - Click "Register Passkey"
   - Optionally enter your username or email for verification
   - Click "Register Passkey" again
   - Follow your device's instructions to create the passkey

2. **Logging in with Passkey**:
   - Go to the WordPress login page
   - Click "Login with Passkey"
   - Use your device's biometric authentication or PIN

1. **Managing Passkeys**:
   - Go to Users → Passkeys in the WordPress admin
   - View which users have registered passkeys
   - See the number of credentials per user
   - Click "View Credentials" to see detailed information
   - Delete credentials if needed

2. **Plugin Settings**:
   - Go to Passkey
   - Configure plugin options:
     - Enable/disable passkey login
     - Require HTTPS
     - Session timeout
     - Maximum credentials per user
     - Session timeout settings
     - Maximum credentials per user


## Shortcodes

The plugin provides two shortcodes for displaying passkey functionality:

### `[mdlogin_passkey_login]`
Displays a passkey login button.

**Example:**
```
[mdlogin_passkey_login]
```

### `[mdlogin_passkey_register]`
Displays a passkey registration form.

**Example:**
```
[mdlogin_passkey_register]
```

## API Endpoints

The plugin provides the following REST API endpoints:

- `POST /wp-json/mdlogin/v1/start-registration` - Start passkey registration
- `POST /wp-json/mdlogin/v1/verify-registration` - Verify registration response
- `POST /wp-json/mdlogin/v1/start-login` - Start passkey login
- `POST /wp-json/mdlogin/v1/verify-login` - Verify login response
- `GET /wp-json/mdlogin/v1/user-credentials` - Get user credentials (admin only)
- `POST /wp-json/mdlogin/v1/delete-credential` - Delete user credential (admin only)

## Browser Support

The plugin requires browsers that support the WebAuthn API:
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 18+

## Device Requirements

- Device with biometric authentication (fingerprint, face recognition)
- Or device with PIN/password capability
- Platform authenticator support

## Security Features

- **Nonce Verification**: All API requests are protected with WordPress nonces
- **Session Management**: Secure session handling with expiration
- **Input Sanitization**: All user inputs are properly sanitized
- **Error Handling**: Comprehensive error handling without exposing sensitive information
- **Credential Storage**: Secure storage of WebAuthn credentials in user meta
- **Database Sessions**: Session data stored in database with automatic cleanup
- **HTTPS Enforcement**: Option to require HTTPS for security

## Development

### File Structure

```
multidots-passkey-login/
├── admin/
│   ├── class-mdlogin-passkey-admin.php         # Admin functionality and settings
│   └── class-mdlogin-passkey-users-list-table.php # Users list table for admin
├── assets/
│   ├── css/
│   │   ├── mdlogin-passkey.css                     # Frontend styles
│   │   └── mdlogin-admin.css                       # Admin styles
│   ├── js/
│   │   ├── mdlogin-passkey.js                      # Frontend JavaScript
│   │   ├── mdlogin-profile.js                      # Profile page JavaScript
│   │   └── mdlogin-admin.js                        # Admin JavaScript
│   └── images/
│       ├── footer-banner.png               # Footer banner image
│       └── MDLOGIN-Logo.svg                # Logo image
├── includes/
│   ├── class-mdlogin-passkey-loader.php        # Plugin loader and initialization
│   ├── class-mdlogin-passkey-webauthn.php      # WebAuthn operations
│   ├── class-mdlogin-passkey-credentials.php   # Credential management
│   ├── class-mdlogin-passkey-api.php           # REST API endpoints
│   ├── class-mdlogin-passkey-profile.php       # User profile integration
│   ├── class-mdlogin-passkey-shortcodes.php    # Shortcode functionality
│   └── class-mdlogin-passkey-i18n.php          # Internationalization
├── languages/ 
├── vendor/                                 # Composer dependencies
├── composer.json                           # Composer configuration
├── composer.lock                           # Composer lock file
├── passkey.php                             # Main plugin file
├── README.md                               # This file
└── README.txt                              # WordPress plugin repository readme
```

### Dependencies

- `web-auth/webauthn-framework`: WebAuthn implementation (v4.9)
- `laminas/laminas-diactoros`: HTTP message implementation

### Development Setup

1. Clone the repository
2. Run `composer install` to install dependencies
3. Run `composer test` to run tests
4. Run `composer phpcs` to check code standards

### Code Standards

The plugin follows WordPress coding standards:
- PSR-4 autoloading
- WordPress coding standards
- Proper documentation and comments
- Security best practices

## Troubleshooting

### Common Issues

1. **"Passkeys are not supported"**
   - Ensure you're using a supported browser
   - Check that your device has biometric authentication or PIN capability
   - Verify the site is running on HTTPS

2. **"Registration failed"**
   - Check that the username exists in WordPress
   - Ensure the user doesn't already have passkey credentials
   - Verify the device supports WebAuthn

3. **"Login failed"**
   - Ensure the username is correct
   - Check that the user has registered passkey credentials
   - Verify the device is the same one used for registration

4. **"Security check failed"**
   - Clear browser cache and cookies
   - Ensure JavaScript is enabled
   - Check for plugin conflicts



## Changelog

### Version 1.0.0
- Initial release with passkey-based login and registration.
- Shortcodes for login and registration forms.
- Admin settings for session timeout, Max Credentials per User, and authentication methods.
- Support for existing and new user registrations.

## License

GPL v2 or later

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.