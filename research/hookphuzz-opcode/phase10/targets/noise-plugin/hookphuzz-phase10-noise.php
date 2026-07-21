<?php
/** Plugin Name: HookPhuzz Phase 10 Noise; Version: 1.0.0 */
function hookphuzz_phase10_noise(): void { wp_send_json_success(['noise' => $_GET['bootstrap_noise'] ?? '']); }
add_action('wp_ajax_nopriv_hookphuzz_phase10_noise', 'hookphuzz_phase10_noise');
