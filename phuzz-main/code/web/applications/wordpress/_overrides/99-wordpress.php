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

// WP checks forced by this file; guard evidence below records calls to exactly these.
$__hookphuzz_overridden_guards = ['current_user_can'];

// The referer overrides still read the nonce field the way WordPress does, so Zend records the
// guard's read in order; the event names the field for the redirect gate (e.g. `security`).
$__hookphuzz_read_nonce_field = static function (string $guard, array $fields): void {
    foreach ($fields as $field) {
        if (!is_string($field) || $field === '' || !isset($_REQUEST[$field])) {
            continue;
        }
        // Keep the read and __LINE__ on one line: the gate matches this exact Zend read event.
        $scalar = is_scalar($_REQUEST[$field]); $read_line = __LINE__;
        $callback = function_exists('__uopz_current_parent_callback_metadata')
            ? __uopz_current_parent_callback_metadata() : null;
        if (isset($GLOBALS['__uopz_request']) && !empty($callback['callback_id'])) {
            $GLOBALS['__uopz_request']['guard_redirect_events'][] = [
                'kind' => 'nonce_field', 'function' => $guard, 'field' => $field, 'scalar' => $scalar,
                'file' => basename(__FILE__), 'line' => $read_line, 'callback_id' => $callback['callback_id'],
            ];
        }
        return;
    }
};

if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) !== '1' ) {
    uopz_set_return('check_admin_referer', static function ($action = -1, $query_arg = '_wpnonce') use (
        $__hookphuzz_read_nonce_field
    ) {
        $__hookphuzz_read_nonce_field('check_admin_referer', [$query_arg]);
        return 1;
    }, true);
    uopz_set_return('wp_verify_nonce', function($nonce, $action) {
        return 1; // valid, generated 0-12h ago
    }, true);
    $__hookphuzz_overridden_guards[] = 'check_admin_referer';
    $__hookphuzz_overridden_guards[] = 'wp_verify_nonce';
}

if ( getenv( 'HOOKPHUZZ_STRICT_NONCE_PROOF' ) !== '1' ) {
    // Same field order as WordPress: the named query arg, then _ajax_nonce, then _wpnonce.
    uopz_set_return('check_ajax_referer', static function ($action = -1, $query_arg = false, $stop = true) use (
        $__hookphuzz_read_nonce_field
    ) {
        $__hookphuzz_read_nonce_field('check_ajax_referer', [$query_arg, '_ajax_nonce', '_wpnonce']);
        return 1;
    }, true);
    $__hookphuzz_overridden_guards[] = 'check_ajax_referer';
}

// Request-scoped fuzz context; absent headers preserve legacy authenticated mode.
$__hookphuzz_auth_context = (string) ($_SERVER['HTTP_X_HOOKPHUZZ_AUTH_CONTEXT'] ?? 'authenticated');
if (!in_array($__hookphuzz_auth_context, ['guest', 'authenticated'], true)) {
    http_response_code(400);
    exit('Invalid HookPhuzz auth context');
}
if (isset($GLOBALS['__uopz_request'])) {
    $GLOBALS['__uopz_request']['auth_context'] = $__hookphuzz_auth_context;
}
if ($__hookphuzz_auth_context === 'guest') {
    uopz_set_return('is_user_logged_in', false);
    uopz_set_return('get_current_user_id', 0);
    uopz_set_return('wp_get_current_user', function () {
        return new WP_User(0);
    }, true);
    uopz_set_return('current_user_can', false);
    uopz_set_return('user_can', false);
    uopz_set_return('is_super_admin', false);
    // Leave get_user_meta unchanged; never redirect guest reads to user 1.
} else {
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
}

if (isset($GLOBALS['__uopz_request']) && function_exists('__uopz_current_parent_callback_metadata')) {
    $__hookphuzz_record_guard_redirect_event = static function (array $event): void {
        $callback = __uopz_current_parent_callback_metadata();
        if (!empty($callback['callback_id'])) {
            $event['callback_id'] = $callback['callback_id'];
            $GLOBALS['__uopz_request']['guard_redirect_events'][] = $event;
        }
    };

    foreach ($__hookphuzz_overridden_guards as $__hookphuzz_guard) {
        uopz_set_hook($__hookphuzz_guard, static function () use (
            $__hookphuzz_record_guard_redirect_event, $__hookphuzz_guard
        ): void {
            $__hookphuzz_record_guard_redirect_event([
                'kind' => 'guard',
                'function' => $__hookphuzz_guard,
            ]);
        });
    }

    // Observe the header emitted by wp_redirect after WordPress filters and sanitization.
    uopz_set_hook('header', static function ($header = null, $replace = true, $response_code = 0) use (
        $__hookphuzz_record_guard_redirect_event
    ): void {
        if (!is_string($header) || strncasecmp($header, 'Location:', 9) !== 0
            || !is_int($response_code) || $response_code < 300 || $response_code >= 400 || headers_sent()) {
            return;
        }
        $caller = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1] ?? [];
        if (($caller['function'] ?? null) === 'wp_redirect' && !isset($caller['class'])) {
            $__hookphuzz_record_guard_redirect_event([
                'kind' => 'redirect',
                'function' => 'wp_redirect',
                'mode' => 'observed',
                'status' => $response_code,
                'location_sha256' => hash('sha256', trim(substr($header, 9), " \t")),
            ]);
        }
    });
}

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
