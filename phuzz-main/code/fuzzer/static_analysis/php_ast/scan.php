<?php

declare(strict_types=1);

use HookPhuzz\StaticAnalysis\PhpAst\Analyzer;
use HookPhuzz\StaticAnalysis\PhpAst\JsonWriter;
use HookPhuzz\StaticAnalysis\PhpAst\Scanner;
use PhpParser\ParserFactory;

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "Missing Composer dependencies. Run: composer install --working-dir " . __DIR__ . PHP_EOL);
    exit(2);
}

require $autoload;

function usage(): string
{
    return implode(PHP_EOL, [
        'Usage:',
        '  php scan.php --source <php-source-dir> --out <artifact-dir> [--include-ast] [--include-skipped]',
        '',
        'Options:',
        '  --source          PHP source directory to scan.',
        '  --out             Output directory for JSON artifacts.',
        '  --include-ast     Include serialized AST in ast_files.jsonl.',
        '  --include-skipped Include skipped directory paths in ast_summary.json.',
        '  --help            Show this help.',
    ]) . PHP_EOL;
}

$options = getopt('', ['source:', 'out:', 'include-ast', 'include-skipped', 'help']);
if (isset($options['help'])) {
    echo usage();
    exit(0);
}

$source = isset($options['source']) ? (string) $options['source'] : '';
$out = isset($options['out']) ? (string) $options['out'] : '';
if ($source === '' || $out === '') {
    fwrite(STDERR, usage());
    exit(1);
}

$parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
$scanner = new Scanner($parser, new Analyzer(), new JsonWriter());

try {
    $summary = $scanner->scan($source, $out, isset($options['include-ast']), isset($options['include-skipped']));
} catch (InvalidArgumentException $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
} catch (RuntimeException $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}

echo 'PHP AST scan summary: files=' . $summary['total_files_scanned']
    . ' parsed=' . $summary['successfully_parsed_files']
    . ' failed=' . $summary['failed_files']
    . ' nodes=' . $summary['total_ast_nodes'] . PHP_EOL;
exit(0);
