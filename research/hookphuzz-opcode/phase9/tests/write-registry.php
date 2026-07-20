<?php
declare(strict_types=1);
[$_, $source, $destination] = $argv;
$json = (string) file_get_contents($source);
if (json_decode($json, true) === null && trim($json) !== 'null') { /* malformed fixtures are intentional */ }
$temp = tempnam(dirname($destination), '.phase9-test-');
if ($temp === false || file_put_contents($temp, $json) !== strlen($json) || !chmod($temp, 0644)) exit(1);
$stream = fopen($temp, 'c+b'); if ($stream === false || !fflush($stream) || (function_exists('fsync') && !fsync($stream))) exit(1); fclose($stream);
if (!rename($temp, $destination)) exit(1);
