<?php

declare(strict_types=1);

namespace HookPhuzz\StaticAnalysis\PhpAst;

use InvalidArgumentException;
use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeAbstract;
use PhpParser\Parser;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;
use Throwable;

final class Scanner
{
    /** @var list<string> */
    private const DEFAULT_SKIP_DIRS = [
        'vendor',
        'node_modules',
        'tests',
        'test',
        'cache',
        '.cache',
        'wp-admin',
        'wp-includes',
    ];

    private Parser $parser;
    private Analyzer $analyzer;
    private JsonWriter $writer;

    public function __construct(Parser $parser, Analyzer $analyzer, JsonWriter $writer)
    {
        $this->parser = $parser;
        $this->analyzer = $analyzer;
        $this->writer = $writer;
    }

    /**
     * @return array<string, mixed>
     */
    public function scan(string $sourceDir, string $outDir, bool $includeAst = false, bool $includeSkipped = false): array
    {
        $sourcePath = realpath($sourceDir);
        if ($sourcePath === false || !is_dir($sourcePath)) {
            throw new InvalidArgumentException('Source directory does not exist: ' . $sourceDir);
        }

        if (!is_dir($outDir) && !mkdir($outDir, 0777, true) && !is_dir($outDir)) {
            throw new RuntimeException('Failed to create output directory: ' . $outDir);
        }

        $startedAt = microtime(true);
        $astRows = [];
        $hookCandidates = [];
        $inputCandidates = [];
        $sinkCandidates = [];
        $skippedDirectories = [];
        $parsedCount = 0;
        $failedCount = 0;
        $totalNodes = 0;

        foreach ($this->phpFiles($sourcePath, $skippedDirectories) as $filePath) {
            $row = [
                'file' => $this->normalizePath($filePath),
                'status' => 'parsed',
                'error' => null,
                'node_count' => 0,
                'top_level_node_types' => [],
            ];

            try {
                $code = file_get_contents($filePath);
                if ($code === false) {
                    throw new RuntimeException('Failed to read PHP file');
                }

                $nodes = $this->parser->parse($code) ?? [];
                $nodeCount = $this->countNodes($nodes);
                $row['node_count'] = $nodeCount;
                $row['top_level_node_types'] = $this->topLevelNodeTypes($nodes);
                if ($includeAst) {
                    $row['ast'] = $this->serializeNodes($nodes);
                }

                $analysis = $this->analyzer->analyze($nodes, $this->normalizePath($filePath));
                $hookCandidates = array_merge($hookCandidates, $analysis['hooks']);
                $inputCandidates = array_merge($inputCandidates, $analysis['inputs']);
                $sinkCandidates = array_merge($sinkCandidates, $analysis['sinks']);
                $parsedCount++;
                $totalNodes += $nodeCount;
            } catch (Error $error) {
                $row['status'] = 'parse_error';
                $row['error'] = $error->getMessage();
                $failedCount++;
            } catch (Throwable $error) {
                $row['status'] = 'scan_error';
                $row['error'] = $error->getMessage();
                $failedCount++;
            }

            $astRows[] = $row;
        }

        $summary = [
            'total_files_scanned' => count($astRows),
            'successfully_parsed_files' => $parsedCount,
            'failed_files' => $failedCount,
            'total_ast_nodes' => $totalNodes,
            'skip_directory_names' => self::DEFAULT_SKIP_DIRS,
            'skipped_directories' => $includeSkipped ? array_values(array_unique($skippedDirectories)) : [],
            'elapsed_time_seconds' => round(microtime(true) - $startedAt, 6),
        ];

        $this->writer->writeJsonLines($outDir . DIRECTORY_SEPARATOR . 'ast_files.jsonl', $astRows);
        $this->writer->writeJson($outDir . DIRECTORY_SEPARATOR . 'ast_summary.json', $summary);
        $this->writer->writeJson($outDir . DIRECTORY_SEPARATOR . 'hook_candidates.json', $hookCandidates);
        $this->writer->writeJson($outDir . DIRECTORY_SEPARATOR . 'input_candidates.json', $inputCandidates);
        $this->writer->writeJson($outDir . DIRECTORY_SEPARATOR . 'sink_candidates.json', $sinkCandidates);

        return $summary;
    }

    /**
     * @param list<string> $skippedDirectories
     * @return iterable<string>
     */
    private function phpFiles(string $sourcePath, array &$skippedDirectories): iterable
    {
        $directory = new RecursiveDirectoryIterator($sourcePath, RecursiveDirectoryIterator::SKIP_DOTS);
        $filter = new RecursiveCallbackFilterIterator(
            $directory,
            function (SplFileInfo $current) use (&$skippedDirectories): bool {
                if (!$current->isDir()) {
                    return true;
                }
                if (in_array($current->getFilename(), self::DEFAULT_SKIP_DIRS, true)) {
                    $skippedDirectories[] = $this->normalizePath($current->getPathname());
                    return false;
                }
                return true;
            }
        );

        $iterator = new RecursiveIteratorIterator($filter);
        foreach ($iterator as $file) {
            if (!$file instanceof SplFileInfo || !$file->isFile()) {
                continue;
            }
            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }
            yield $file->getPathname();
        }
    }

    /**
     * @param list<Node> $nodes
     */
    private function countNodes(array $nodes): int
    {
        $count = 0;
        foreach ($nodes as $node) {
            $count++;
            foreach ($node->getSubNodeNames() as $name) {
                $value = $node->$name;
                if ($value instanceof Node) {
                    $count += $this->countNodes([$value]);
                } elseif (is_array($value)) {
                    $childNodes = array_values(array_filter($value, static fn ($item): bool => $item instanceof Node));
                    $count += $this->countNodes($childNodes);
                }
            }
        }
        return $count;
    }

    /**
     * @param list<Node> $nodes
     * @return list<string>
     */
    private function topLevelNodeTypes(array $nodes): array
    {
        return array_values(array_map(static fn (Node $node): string => $node->getType(), $nodes));
    }

    /**
     * @param list<Node> $nodes
     * @return list<array<string, mixed>>
     */
    private function serializeNodes(array $nodes): array
    {
        return array_map(fn (Node $node): array => $this->serializeNode($node), $nodes);
    }

    /**
     * @return array<string, mixed>
     */
    private function serializeNode(Node $node): array
    {
        $payload = [
            'type' => $node->getType(),
            'line' => $node->getStartLine(),
        ];
        foreach ($node->getSubNodeNames() as $name) {
            $value = $node->$name;
            if ($value instanceof Node) {
                $payload[$name] = $this->serializeNode($value);
            } elseif (is_array($value)) {
                $payload[$name] = array_map(function ($item) {
                    return $item instanceof Node ? $this->serializeNode($item) : $item;
                }, $value);
            } elseif ($value instanceof NodeAbstract) {
                $payload[$name] = (string) $value;
            } else {
                $payload[$name] = $value;
            }
        }
        return $payload;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', $path);
    }
}
