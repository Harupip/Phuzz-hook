<?php

declare(strict_types=1);

namespace HookPhuzz\StaticAnalysis\PhpAst;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpParser\PrettyPrinter\Standard;

final class Analyzer
{
    /** @var list<string> */
    private const HOOK_FUNCTIONS = ['add_action', 'add_filter', 'do_action', 'apply_filters'];

    /** @var list<string> */
    private const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE'];

    /** @var list<string> */
    private const FUNCTION_SINKS = [
        'mysqli_query',
        'system',
        'exec',
        'shell_exec',
        'passthru',
        'file_get_contents',
        'fopen',
        'file',
        'unlink',
        'readfile',
        'unserialize',
        'maybe_unserialize',
        'wp_redirect',
        'wp_safe_redirect',
    ];

    /** @var list<string> */
    private const WPDB_METHOD_SINKS = ['query', 'get_results', 'get_var'];

    /** @var list<string> */
    private const GENERIC_METHOD_SINKS = ['query', 'exec', 'loadXML', 'load'];

    private Standard $prettyPrinter;

    public function __construct()
    {
        $this->prettyPrinter = new Standard();
    }

    /**
     * @param list<Node> $nodes
     * @return array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>}
     */
    public function analyze(array $nodes, string $file): array
    {
        $results = ['hooks' => [], 'inputs' => [], 'sinks' => []];
        foreach ($nodes as $node) {
            $this->walk($node, $file, ['class' => null, 'function' => null, 'method' => null], $results);
        }
        return $results;
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function walk(Node $node, string $file, array $context, array &$results): void
    {
        $context = $this->updateContext($node, $context);

        if ($node instanceof Expr\FuncCall) {
            $this->collectFunctionCall($node, $file, $context, $results);
        } elseif ($node instanceof Expr\MethodCall) {
            $this->collectMethodCall($node, $file, $context, $results);
        } elseif ($node instanceof Expr\StaticCall) {
            $this->collectStaticCall($node, $file, $context, $results);
        } elseif ($node instanceof Expr\ArrayDimFetch) {
            $this->collectSuperglobalRead($node, $file, $context, $results);
        } elseif ($node instanceof Expr\Include_) {
            $this->collectIncludeSink($node, $file, $context, $results);
        }

        foreach ($node->getSubNodeNames() as $name) {
            $value = $node->$name;
            if ($value instanceof Node) {
                $this->walk($value, $file, $context, $results);
            } elseif (is_array($value)) {
                foreach ($value as $item) {
                    if ($item instanceof Node) {
                        $this->walk($item, $file, $context, $results);
                    }
                }
            }
        }
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @return array{class: ?string, function: ?string, method: ?string}
     */
    private function updateContext(Node $node, array $context): array
    {
        if ($node instanceof Stmt\Class_) {
            $context['class'] = $node->name ? $node->name->toString() : null;
            $context['method'] = null;
        } elseif ($node instanceof Stmt\Function_) {
            $context['function'] = $node->name->toString();
            $context['method'] = null;
        } elseif ($node instanceof Stmt\ClassMethod) {
            $context['method'] = $node->name->toString();
            $context['function'] = null;
        }
        return $context;
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function collectFunctionCall(Expr\FuncCall $node, string $file, array $context, array &$results): void
    {
        $functionName = $this->nameToString($node->name);
        $lowerName = strtolower($functionName);

        if (in_array($lowerName, self::HOOK_FUNCTIONS, true)) {
            $hookArg = $node->args[0] ?? null;
            $hookName = $hookArg ? $this->staticString($hookArg->value) : null;
            $results['hooks'][] = [
                'file' => $file,
                'line' => $node->getStartLine(),
                'function_name' => $lowerName,
                'hook_name' => $hookName,
                'is_dynamic' => $hookName === null,
                'hook_expression' => $hookArg ? $this->pretty($hookArg->value) : null,
                'callback' => isset($node->args[1]) ? $this->pretty($node->args[1]->value) : null,
                'priority' => isset($node->args[2]) ? $this->staticInt($node->args[2]->value) : null,
                'accepted_args' => isset($node->args[3]) ? $this->staticInt($node->args[3]->value) : null,
                'context' => $this->contextPayload($context),
            ];
        }

        if ($lowerName === 'filter_input') {
            $source = isset($node->args[0]) ? $this->inputSourceFromArg($node->args[0]) : null;
            $parameterName = isset($node->args[1]) ? $this->staticString($node->args[1]->value) : null;
            if ($source !== null) {
                $results['inputs'][] = [
                    'file' => $file,
                    'line' => $node->getStartLine(),
                    'source' => $source,
                    'parameter_name' => $parameterName,
                    'context' => $this->contextPayload($context),
                ];
            }
        }

        if (in_array($lowerName, self::FUNCTION_SINKS, true)) {
            if ($lowerName !== 'header' || $this->isLocationHeader($node)) {
                $results['sinks'][] = $this->sinkPayload($file, $node->getStartLine(), $lowerName, $context);
            }
        } elseif ($lowerName === 'header' && $this->isLocationHeader($node)) {
            $results['sinks'][] = $this->sinkPayload($file, $node->getStartLine(), 'header(Location)', $context);
        }
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function collectMethodCall(Expr\MethodCall $node, string $file, array $context, array &$results): void
    {
        $method = $this->nodeIdentifier($node->name);
        if ($method === null) {
            return;
        }
        $lowerMethod = strtolower($method);
        $sinkName = null;

        if ($node->var instanceof Expr\Variable && $node->var->name === 'wpdb' && in_array($lowerMethod, self::WPDB_METHOD_SINKS, true)) {
            $sinkName = '$wpdb->' . $lowerMethod;
        } elseif (in_array($method, self::GENERIC_METHOD_SINKS, true) || in_array($lowerMethod, self::GENERIC_METHOD_SINKS, true)) {
            $sinkName = '->' . $method;
        }

        if ($sinkName !== null) {
            $results['sinks'][] = $this->sinkPayload($file, $node->getStartLine(), $sinkName, $context);
        }
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function collectStaticCall(Expr\StaticCall $node, string $file, array $context, array &$results): void
    {
        $class = $this->nameToString($node->class);
        $method = $this->nodeIdentifier($node->name);
        if ($class === '' || $method === null) {
            return;
        }
        $sinkName = $class . '::' . $method;
        if (in_array($sinkName, ['PDO::query', 'PDO::exec', 'DOMDocument::loadXML', 'DOMDocument::load'], true)) {
            $results['sinks'][] = $this->sinkPayload($file, $node->getStartLine(), $sinkName, $context);
        }
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function collectSuperglobalRead(Expr\ArrayDimFetch $node, string $file, array $context, array &$results): void
    {
        if (!$node->var instanceof Expr\Variable || !is_string($node->var->name)) {
            return;
        }
        if (!in_array($node->var->name, self::SUPERGLOBALS, true)) {
            return;
        }

        $results['inputs'][] = [
            'file' => $file,
            'line' => $node->getStartLine(),
            'source' => substr($node->var->name, 1),
            'parameter_name' => $node->dim instanceof Node ? $this->staticString($node->dim) : null,
            'context' => $this->contextPayload($context),
        ];
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @param array{hooks: list<array<string, mixed>>, inputs: list<array<string, mixed>>, sinks: list<array<string, mixed>>} $results
     */
    private function collectIncludeSink(Expr\Include_ $node, string $file, array $context, array &$results): void
    {
        $names = [
            Expr\Include_::TYPE_INCLUDE => 'include',
            Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Expr\Include_::TYPE_REQUIRE => 'require',
            Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
        ];
        $results['sinks'][] = $this->sinkPayload($file, $node->getStartLine(), $names[$node->type] ?? 'include', $context);
    }

    private function nameToString($node): string
    {
        if ($node instanceof Name) {
            return $node->toString();
        }
        if ($node instanceof Node\Identifier) {
            return $node->toString();
        }
        return $node instanceof Node ? $this->pretty($node) : '';
    }

    private function nodeIdentifier($node): ?string
    {
        if ($node instanceof Node\Identifier) {
            return $node->toString();
        }
        return null;
    }

    private function staticString(Node $node): ?string
    {
        return $node instanceof Scalar\String_ ? $node->value : null;
    }

    private function staticInt(Node $node): ?int
    {
        return $node instanceof Scalar\LNumber ? $node->value : null;
    }

    private function inputSourceFromArg(Arg $arg): ?string
    {
        if (!$arg->value instanceof Expr\ConstFetch) {
            return null;
        }
        $name = strtoupper($arg->value->name->toString());
        if (strpos($name, 'INPUT_') !== 0) {
            return null;
        }
        return substr($name, 6);
    }

    private function isLocationHeader(Expr\FuncCall $node): bool
    {
        if (!isset($node->args[0])) {
            return false;
        }
        $value = $this->staticString($node->args[0]->value);
        return $value !== null && stripos($value, 'Location:') === 0;
    }

    private function pretty(Node $node): string
    {
        return $this->prettyPrinter->prettyPrintExpr($node);
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @return array{class: ?string, function: ?string, method: ?string}
     */
    private function contextPayload(array $context): array
    {
        return $context;
    }

    /**
     * @param array{class: ?string, function: ?string, method: ?string} $context
     * @return array<string, mixed>
     */
    private function sinkPayload(string $file, int $line, string $sinkName, array $context): array
    {
        return [
            'file' => $file,
            'line' => $line,
            'sink_name' => $sinkName,
            'context' => $this->contextPayload($context),
        ];
    }
}
