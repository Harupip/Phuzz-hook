<?php
/**
 * Plugin Name: Phase 4 Multi Reader Fixture
 */

class ExampleInput {
    public static function post($key) {
        return $_POST[$key] ?? null;
    }

    public function get($key) {
        return $_GET[$key] ?? null;
    }
}

class Phase4MultiReaderController {
    public static function handle() {
        $post_value = ExampleInput::post('runtime_only_field');
        $get_value = (new ExampleInput())->get('runtime_query_field');
        ExampleInput::post('runtime_only_field');
        (new ExampleInput())->get('runtime_query_field');
    echo wp_json_encode([
        'post_value' => $post_value,
        'get_value' => $get_value,
    ]);
        wp_die();
    }
}

add_action('wp_ajax_phase4_multi_reader', [Phase4MultiReaderController::class, 'handle']);
