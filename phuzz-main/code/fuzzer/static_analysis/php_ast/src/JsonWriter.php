<?php

declare(strict_types=1);

namespace HookPhuzz\StaticAnalysis\PhpAst;

use RuntimeException;

final class JsonWriter
{
    /**
     * @param array<string, mixed> $payload
     */
    public function writeJson(string $path, array $payload): void
    {
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new RuntimeException('Failed to encode JSON for ' . $path);
        }
        $this->writeFile($path, $json . PHP_EOL);
    }

    /**
     * @param list<array<string, mixed>> $rows
     */
    public function writeJsonLines(string $path, array $rows): void
    {
        $lines = [];
        foreach ($rows as $row) {
            $json = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($json === false) {
                throw new RuntimeException('Failed to encode JSONL row for ' . $path);
            }
            $lines[] = $json;
        }
        $this->writeFile($path, implode(PHP_EOL, $lines) . (count($lines) > 0 ? PHP_EOL : ''));
    }

    private function writeFile(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents) === false) {
            throw new RuntimeException('Failed to write ' . $path);
        }
    }
}
