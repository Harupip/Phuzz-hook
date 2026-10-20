import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[2]


class PluginZipDirectoryTests(unittest.TestCase):
    def test_preferred_directory_falls_back_per_plugin_and_menu_lists_both(self):
        # Organizing archives must not hide plugins left in the original folder.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "web/applications/wordpress/_plugins"
            preferred = original / "chosen folder"
            preferred.mkdir(parents=True)
            (original / "fallback.zip").touch()
            (original / "same.zip").touch()
            (preferred / "same.zip").touch()
            (preferred / "preferred.zip").touch()
            (preferred / "not-an-archive.zip").mkdir()
            (root / "phuzz.env").write_text('PLUGIN_ZIP_DIR="web/applications/wordpress/_plugins/chosen folder"\n')
            wrapper = (CODE_DIR / "phuzz.ps1").read_text(encoding="utf-8-sig")
            menu = "function Get-LocalPluginSlugs" + wrapper.split("function Get-LocalPluginSlugs", 1)[1].split("function Read-PluginSlug", 1)[0]
            probe = root / "probe.ps1"
            probe.write_text(r'''
param($CodeDir, $Root)
$ErrorActionPreference = "Stop"
. (Join-Path $CodeDir "scripts/wordpress/read-phuzz-env.ps1")
$scriptRoot = $Root
$pluginDir = Join-Path $Root "web/applications/wordpress/_plugins"
$runtimeSettings = Resolve-PhuzzRuntimeSettings -Path (Join-Path $Root "phuzz.env") -BoundParameters @{}
$pluginZipDir = $runtimeSettings["PluginZipDirectory"]
''' + menu + r'''
@{
    preferred = Resolve-PhuzzPluginZip -ScriptRoot $Root -PluginZipDirectory $pluginZipDir -PluginSlug same
    fallback = Resolve-PhuzzPluginZip -ScriptRoot $Root -PluginZipDirectory $pluginZipDir -PluginSlug fallback
    slugs = @(Get-LocalPluginSlugs)
} | ConvertTo-Json -Compress
''', encoding="utf-8")
            result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe), str(CODE_DIR), str(root)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            state = json.loads(result.stdout)
            self.assertEqual(Path(state["preferred"]), preferred / "same.zip")
            self.assertEqual(Path(state["fallback"]), original / "fallback.zip")
            self.assertEqual(state["slugs"], ["fallback", "preferred", "same"])

    def test_empty_absolute_and_missing_directories_keep_original_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / "chosen folder"
            preferred.mkdir()
            (preferred / "demo.zip").touch()
            probe = root / "probe.ps1"
            probe.write_text(r'''
param($CodeDir, $Root)
$ErrorActionPreference = "Stop"
. (Join-Path $CodeDir "scripts/wordpress/read-phuzz-env.ps1")
$settings = Resolve-PhuzzRuntimeSettings -Path (Join-Path $Root "phuzz.env") -BoundParameters @{}
Resolve-PhuzzPluginZip -ScriptRoot $Root -PluginZipDirectory $settings["PluginZipDirectory"] -PluginSlug demo
''', encoding="utf-8")
            for configured in ("", str(preferred), str(root / "missing")):
                with self.subTest(configured=configured):
                    (root / "phuzz.env").write_text(f'PLUGIN_ZIP_DIR="{configured}"\n')
                    result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe), str(CODE_DIR), str(root)], capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = preferred / "demo.zip" if configured == str(preferred) else root / "web/applications/wordpress/_plugins/demo.zip"
                    self.assertEqual(Path(result.stdout.strip()), expected)

    def test_compose_mounts_preferred_archives_and_keeps_original_directory(self):
        # Both target and dependency ZIPs must reach the install script, while
        # archives remaining outside the preferred directory stay accessible.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / "chosen folder"
            preferred.mkdir()
            for name in ("demo.zip", "woocommerce.zip"):
                (preferred / name).touch()
            runner = (CODE_DIR / "scripts/wordpress/run-wordpress-phuzz.ps1").read_text(encoding="utf-8-sig")
            function = "function New-PluginOverrideFile" + runner.split("function New-PluginOverrideFile", 1)[1].split("function Assert-PathExists", 1)[0]
            probe = root / "probe.ps1"
            probe.write_text(r'''
param($Root, $Preferred)
$ErrorActionPreference = "Stop"
$env:TEMP = $Root
$pluginZipDir = $Preferred
$fuzzerService = "fuzzer-wordpress-plugin"
''' + function + '\nNew-PluginOverrideFile -PluginSlug demo -BootstrapConfigSlug wordpress/bootstrap-generated -UseZendDiscovery\n', encoding="utf-8")
            result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe), str(root), str(preferred)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            composed = subprocess.run(["docker", "compose", "-f", str(CODE_DIR / "docker-compose.yml"), "-f", result.stdout.strip(), "config", "--format", "json"], cwd=CODE_DIR, capture_output=True, text=True, timeout=30)
            self.assertEqual(composed.returncode, 0, composed.stderr)
            volumes = json.loads(composed.stdout)["services"]["web"]["volumes"]
            by_target = {volume["target"].rstrip("/"): volume for volume in volumes}
            self.assertIn("/applications", by_target)
            mounted = by_target["/plugin-zips"]
            self.assertEqual(Path(mounted["source"]), preferred)
            self.assertTrue(mounted["read_only"])
            self.assertFalse(any(target.endswith(".zip") for target in by_target))

    def test_install_recipe_uses_preferred_target_and_dependency_fallback(self):
        bash = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
        source = (CODE_DIR / "web/applications/wordpress/init.sh").read_text(encoding="utf-8")
        recipe = "resolve_plugin_zip()" + source.split("resolve_plugin_zip()", 1)[1].split("\nEOF", 1)[0] + "\nEOF\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / "chosen folder"
            preferred.mkdir()
            (preferred / "udraw.zip").touch()
            original = root / "_plugins"
            original.mkdir()
            (original / "woocommerce.zip").touch()
            probe = root / "probe.sh"
            probe.write_text(recipe.replace("/plugin-zips/", preferred.as_posix() + "/"), encoding="utf-8", newline="\n")
            env = dict(os.environ, WP_TARGET_PLUGIN="udraw")
            result = subprocess.run([bash, str(probe)], cwd=root, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = (root / "install.sh").read_text()
            self.assertIn(f'plugin install "{preferred.as_posix()}/udraw.zip" --activate', installed)
            self.assertIn('plugin install "./_plugins/woocommerce.zip" --activate', installed)
            checked = subprocess.run([bash, "-n", str(root / "install.sh")], capture_output=True, text=True, timeout=20)
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
