<?php

##########################################################################################
#                               WP auth function overrides                               #
##########################################################################################
// Workaround to make the front page work, but this is not needed for the plugin fuzzing/evaluation
if ( !function_exists( 'get_current_screen' ) ) {
   require_once '/var/www/html/wp-admin/includes/screen.php';
}
// END workaround
uopz_set_return('is_admin', true); // this appears to "break" the default page/view, but does not affect the API, which we fuzz. => Not if we define the get_current_screen function!

if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) !== '1' ) {
    uopz_set_return('check_admin_referer', 1);
    uopz_set_return('wp_verify_nonce', function($nonce, $action) {
        return 1; // valid, generated 0-12h ago
    }, true);
}

if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) !== '1' ) {
    uopz_set_return('check_ajax_referer', 1);
}

uopz_set_return('current_user_can', true);

uopz_set_return("get_current_user_id", 1);

uopz_set_return('get_user_meta', function ($user_id, $key = '', $single = false) {
    $admin_user_id = 1;
    return get_user_meta($admin_user_id, $key, $single);
}, true);


uopz_set_return('is_super_admin', true);

uopz_set_return('is_user_logged_in', true);

uopz_set_return('user_can', true);

uopz_set_return('wp_get_current_user', function () {
    $admin_user_id = 1;
    return get_user_by('ID', $admin_user_id);
}, true);

if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) === '1' ) {
    $nonce_proof_dir = '/shared-tmpfs/hook-coverage/nonce-proof';
    if ( ! is_dir( $nonce_proof_dir ) ) {
        @mkdir( $nonce_proof_dir, 0777, true );
    }
    $nonce_proof_request_id = preg_replace(
        '/[^A-Za-z0-9_.-]/',
        '_',
        (string) ( $_SERVER['HTTP_X_HOOKPHUZZ_REQUEST_ID'] ?? 'unknown-request' )
    );
    $prepend_body = file_get_contents( 'php://input' );
    $prepend_params = array();
    parse_str( (string) $prepend_body, $prepend_params );
    $prepend_action = (string) ( $prepend_params['action'] ?? '' );
    if ( strpos( $prepend_action, 'lp_async_' ) === 0 ) {
        @file_put_contents(
            $nonce_proof_dir . '/' . $nonce_proof_request_id . '.json',
            json_encode(
                array(
                    'request_id' => $nonce_proof_request_id,
                    'nonce_action' => $prepend_action,
                    'authenticated_user_id' => 1,
                    'authenticated' => true,
                    'session_token_present' => false,
                    'handler_executed' => false,
                    'nonce_rejected' => true,
                    'context_source' => 'strict_auth_override',
                ),
                JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
            )
        );
    }
    if ( function_exists( 'add_action' ) ) {
        add_action( 'wp_loaded', static function () use ( $nonce_proof_dir, $nonce_proof_request_id ): void {
        $raw_body = file_get_contents( 'php://input' );
        $raw_params = array();
        parse_str( (string) $raw_body, $raw_params );
        $candidate_action = isset( $_POST['action'] ) ? (string) $_POST['action'] : (string) ( $raw_params['action'] ?? '' );
        if ( strpos( $candidate_action, 'lp_async_' ) !== 0 ) {
            return;
        }
        $nonce_proof_path = $nonce_proof_dir . '/' . $nonce_proof_request_id . '.json';
        $current_user     = wp_get_current_user();
        $user_id          = is_object( $current_user ) && isset( $current_user->ID ) ? (int) $current_user->ID : 0;
        $session_token    = wp_get_session_token();
        $handler_executed = false;
        $write_nonce_state = static function ( $executed ) use ( $nonce_proof_path, $nonce_proof_request_id, $candidate_action, $user_id, $session_token ): void {
            $record = array(
                'request_id' => $nonce_proof_request_id,
                'nonce_action' => $candidate_action,
                'authenticated_user_id' => $user_id,
                'authenticated' => $user_id > 0,
                'session_token_present' => (string) $session_token !== '',
                'handler_executed' => (bool) $executed,
                'nonce_rejected' => ! $executed,
            );
            @file_put_contents(
                $nonce_proof_path,
                wp_json_encode( $record, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT )
            );
        };
        $write_nonce_state( false );
        $handler_hook = static function () use ( &$handler_executed, $write_nonce_state ): void {
            $handler_executed = true;
            $write_nonce_state( true );
        };
        foreach ( array( 'LP_Background_Single_Course', 'LP_Background_Single_Email', 'LP_Background_Thim_Cache' ) as $class ) {
            if ( class_exists( $class ) && method_exists( $class, 'handle' ) ) {
                @uopz_set_hook( $class, 'handle', $handler_hook );
            }
        }
        }, 999 );
    }
}

?>
