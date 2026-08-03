<?php
/** Plugin Name: HookPhuzz Phase 13 Local Containment */
add_filter('pre_wp_mail', static function () { return true; }, PHP_INT_MAX);
add_filter('pre_http_request', static function ($pre, $args, $url) {
    $host = parse_url((string) $url, PHP_URL_HOST);
    return in_array($host, ['localhost', 'web', 'db'], true) ? $pre : new WP_Error('phase13_outbound_blocked');
}, PHP_INT_MAX, 3);
