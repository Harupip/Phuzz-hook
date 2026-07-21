<?php
declare(strict_types=1);
header('Content-Type: application/json');
echo json_encode(['hookphuzz_opcode_phase5' => extension_loaded('hookphuzz_opcode_phase5')], JSON_THROW_ON_ERROR), "\n";
