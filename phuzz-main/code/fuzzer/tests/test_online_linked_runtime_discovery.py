import unittest

from online_linked.coordination.runtime_discovery import (
    foreign_callback,
    merge_registry_callback,
    registered_child_callback,
)


VERSION = {"callback_id": "cb-parent", "hook_name": "wp_ajax_parent"}


class ForeignCallbackTests(unittest.TestCase):
    def test_foreign_callback_only_when_explicit_and_different(self):
        """A request that names another callback or hook belongs to a different action; a request
        that names nothing, or names the running version itself, is the version's own evidence."""
        self.assertIsNone(foreign_callback({"callback_id": "cb-parent"}, VERSION))
        self.assertIsNone(foreign_callback({"callback_id": "", "hook_name": " "}, VERSION))
        self.assertIsNone(foreign_callback({}, VERSION))
        self.assertIsNone(foreign_callback(
            {"callback_id": "cb-parent", "hook_name": "wp_ajax_parent"}, VERSION,
        ))
        self.assertEqual(foreign_callback({"hook_name": "other_hook"}, VERSION), ("", "other_hook"))
        self.assertEqual(
            foreign_callback({"callback_id": " cb-other ", "hook_name": "wp_ajax_parent"}, VERSION),
            ("cb-other", "wp_ajax_parent"),
        )


def child(**fields):
    return {
        "hook_name": "wp_ajax_child",
        "registered_inside_callback": True,
        "parent_callback_id": "cb-parent",
        **fields,
    }


def register(fallback_id, raw_callback):
    return registered_child_callback(
        fallback_id, raw_callback,
        parent_callback_id="cb-parent", parent_hook_name="wp_ajax_parent",
        request_id="req-1", plugin_slug="fixture",
    )


class RegisteredChildCallbackTests(unittest.TestCase):
    def test_registered_child_callback_filters(self):
        """Only callbacks registered at runtime inside the running parent may become child
        candidates; anything else would queue an action the parent never proved reachable."""
        rejected = {
            "not_mapping": ["cb-x"],
            "missing_hook": child(hook_name=""),
            "is_parent": child(callback_id="cb-parent"),
            "not_registered_inside": child(registered_inside_callback=False),
            "other_parent": child(parent_callback_id="cb-other",
                                  parent_callback={"callback_id": "cb-other", "hook_name": "other"}),
        }
        for label, raw in rejected.items():
            with self.subTest(label):
                self.assertIsNone(register("cb-x", raw))

        callback, callback_id, hook_name = register(" cb-fallback ", child(target_plugin="other-plugin"))
        self.assertEqual((callback_id, hook_name), ("cb-fallback", "wp_ajax_child"))
        self.assertEqual(callback["callback_id"], "cb-fallback")
        self.assertEqual(callback["request_id"], "req-1")
        self.assertEqual(callback["target_plugin"], "other-plugin")

    def test_registered_child_callback_matches_parent_by_hook_or_nested_parent(self):
        """The parent is identified by id or by hook, either flat or inside parent_callback; the
        returned dict is a copy so the runtime report is not rewritten."""
        raw = {"hook_name": "wp_ajax_child", "registered_inside_callback": True,
               "callback_id": "cb-child", "parent_callback": {"hook_name": "wp_ajax_parent"}}
        callback, callback_id, _ = register("ignored", raw)
        self.assertEqual(callback_id, "cb-child")
        self.assertEqual(callback["target_plugin"], "fixture")
        self.assertNotIn("target_plugin", raw)


class MergeRegistryCallbackTests(unittest.TestCase):
    def test_merge_registry_callback_writes_only_new_registrations(self):
        """The registry file is rewritten only when a registration is added; a changed repr only
        updates callback_map, so returning True there would rewrite the file for nothing."""
        registry = {"callback_map": {}}
        callback = {"callback_id": "cb-child", "callback_repr": "Child::handle"}
        self.assertIs(merge_registry_callback(registry, callback), True)
        self.assertEqual(registry["registrations"], [{
            "callback_id": "cb-child", "callback": "Child::handle",
            "canonical_callback": "Child::handle", "callback_type": "static_method",
        }])

        self.assertIs(merge_registry_callback(registry, {**callback, "callback_repr": "child_handle"}), False)
        self.assertEqual(len(registry["registrations"]), 1)
        self.assertEqual(registry["callback_map"], {"cb-child": "child_handle"})

    def test_merge_registry_callback_repairs_invalid_containers(self):
        """A malformed registry section is replaced instead of crashing discovery."""
        registry = {"callback_map": ["bad"], "registrations": "bad"}
        self.assertIs(merge_registry_callback(registry, {"callback_id": "cb-f"}), True)
        self.assertEqual(registry["callback_map"], {"cb-f": "cb-f"})
        self.assertEqual(registry["registrations"][0]["callback_type"], "function")
        self.assertIs(merge_registry_callback({}, {"callback_id": " "}), False)


if __name__ == "__main__":
    unittest.main()
