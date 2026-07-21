<?php
declare(strict_types=1);

$artifact = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
if (($artifact['event_count'] ?? null) !== 4096 || ($artifact['dropped_event_count'] ?? null) !== 1) exit(1);
foreach ([$artifact['events'][0] ?? null, $artifact['events'][4095] ?? null] as $event) {
    if (!is_array($event) || $event['source'] !== 'GET' || $event['path'] !== ['event_cap']
        || $event['operation'] !== 'read' || $event['function'] !== 'phase5_event_cap') exit(1);
}
