<?php
declare(strict_types=1);
require __DIR__ . '/common.php';
function phase5_event_cap(): void {
    for ($index = 0; $index < 4097; $index++) { $_GET['event_cap']; }
}
phase5_event_cap();
phase5_response('event-cap');
