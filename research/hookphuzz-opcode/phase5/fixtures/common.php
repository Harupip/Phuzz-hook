<?php
declare(strict_types=1);

function phase5_headers(string $fixture): void
{
    header('Content-Type: application/json');
    header('X-Phase5-Fixture: ' . $fixture);
}

function phase5_response(string $fixture, array $extra = []): void
{
    phase5_headers($fixture);
    echo json_encode(['fixture' => $fixture] + $extra, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
}
