#!/usr/bin/env python3
"""Local Git fixtures for the upstream tag copy; no network or credentials.

The fork's REST API is played by a function that applies each request to a local bare
repository, so the copy's own code runs unchanged.
"""
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("tags", Path(__file__).with_name("upstream-tags.py"))
tags = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tags)


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.upstream, self.origin, self.work = (str(root / n) for n in ("upstream", "origin.git", "work.git"))
        self.requests, self.skew = [], False
        self.git(root, "init", "-q", "-b", "main", self.upstream)
        self.git(self.upstream, "config", "user.name", "Test")
        self.git(self.upstream, "config", "user.email", "test@example.invalid")
        self.commit("one")
        self.git(self.upstream, "tag", "v0.1.0")
        self.commit("two")
        self.git(self.upstream, "tag", "-a", "-m", "release", "v0.2.0")
        self.git(self.upstream, "tag", "node-sdk/v0.1.0")
        self.git(root, "init", "-q", "--bare", self.origin)
        self.git(root, "init", "-q", "--bare", self.work)
        # The fork already holds upstream's commits through its merges.
        self.git(self.upstream, "push", "-q", self.origin, "main")
        self.publish = tags.api_publisher("example/fork", run=self.fake_api)

    def git(self, cwd, *args, stdin=None):
        return subprocess.run(["git", *args], cwd=cwd, check=True, text=True, capture_output=True,
                              input=stdin).stdout.strip()

    def commit(self, name):
        (Path(self.upstream) / name).write_text(name)
        self.git(self.upstream, "add", name)
        self.git(self.upstream, "commit", "-q", "-m", name)

    def mirror(self):
        return tags.mirror(self.work, self.origin, self.publish, self.upstream)

    def refuse(self, args, reason):
        return subprocess.CompletedProcess(args, 1, "", f"gh: {reason} (HTTP 422)\n")

    def fake_api(self, args, input, text, capture_output):
        """What `gh api --method POST repos/example/fork/<path> --input -` does to the fork."""
        path, body = args[4].removeprefix("repos/example/fork/"), json.loads(input)
        self.requests.append((path, body))
        if path == "git/tags":
            when = datetime.fromisoformat(body["tagger"]["date"])
            offset = when.utcoffset().total_seconds() // 60
            zone = f"{'-' if offset < 0 else '+'}{int(abs(offset)) // 60:02d}{int(abs(offset)) % 60:02d}"
            tagger = body["tagger"]
            content = (f"object {body['object']}\ntype {body['type']}\ntag {body['tag']}\n"
                       f"tagger {tagger['name']} <{tagger['email']}> {int(when.timestamp())} {zone}\n\n"
                       f"{body['message']}{'x' if self.skew else ''}")
            sha = self.git(self.origin, "hash-object", "-t", "tag", "-w", "--stdin", stdin=content)
            return subprocess.CompletedProcess(args, 0, json.dumps({"sha": sha}), "")
        if subprocess.run(["git", "cat-file", "-e", body["sha"]], cwd=self.origin, capture_output=True).returncode:
            return self.refuse(args, "Object does not exist")
        if subprocess.run(["git", "rev-parse", "-q", "--verify", body["ref"]], cwd=self.origin,
                          capture_output=True).returncode == 0:
            return self.refuse(args, "Reference already exists")
        self.git(self.origin, "update-ref", body["ref"], body["sha"])
        return subprocess.CompletedProcess(args, 0, json.dumps({"ref": body["ref"]}), "")

    def kept(self):
        return tags.refs(self.git(self.origin, "for-each-ref", "--format=%(objectname) %(refname)", tags.PREFIX),
                         tags.PREFIX)

    def test_copies_every_tag_under_prefix_with_its_objects(self):
        copied, failures = self.mirror()
        self.assertEqual(failures, [])
        self.assertEqual(sorted(copied), ["node-sdk/v0.1.0", "v0.1.0", "v0.2.0"])
        upstream = tags.refs(self.git(self.upstream, "for-each-ref", "--format=%(objectname) %(refname)",
                                      "refs/tags/"), "refs/tags/")
        self.assertEqual(self.kept(), upstream)
        # The annotated tag keeps its tag object, and its commit is present.
        self.assertEqual(self.git(self.origin, "cat-file", "-t", "refs/tags/upstream/v0.2.0"), "tag")
        self.assertEqual(self.git(self.origin, "rev-parse", "refs/tags/upstream/v0.2.0^{commit}"),
                         self.git(self.upstream, "rev-parse", "v0.2.0^{commit}"))
        # Nothing outside the prefix is created.
        self.assertEqual(self.git(self.origin, "for-each-ref", "--format=%(refname)", "refs/tags/v0.1.0"), "")

    def test_only_the_rest_api_is_used_and_only_to_create(self):
        self.mirror()
        self.assertEqual({path for path, _ in self.requests}, {"git/tags", "git/refs"})
        self.assertTrue(all(body["ref"].startswith(tags.PREFIX) for path, body in self.requests
                            if path == "git/refs"))

    def test_rerun_copies_only_new_tags(self):
        self.mirror()
        self.commit("three")
        self.git(self.upstream, "push", "-q", self.origin, "main")
        self.git(self.upstream, "tag", "v0.3.0")
        self.assertEqual(self.mirror(), (["v0.3.0"], []))

    def test_moved_upstream_tag_never_moves_the_kept_copy(self):
        self.mirror()
        before = self.kept()["v0.1.0"]
        self.git(self.upstream, "tag", "-f", "v0.1.0", "HEAD")
        copied, failures = self.mirror()
        self.assertEqual(copied, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("v0.1.0", failures[0])
        self.assertEqual(self.kept()["v0.1.0"], before)

    def test_a_refused_create_never_overwrites_an_existing_tag(self):
        self.mirror()
        before = self.kept()["v0.1.0"]
        # Even with the plan's own check out of the way, the API refuses an existing name.
        reason = self.publish(self.work, self.git(self.upstream, "rev-parse", "HEAD"), "v0.1.0")
        self.assertEqual(reason, "gh: Reference already exists (HTTP 422)")
        self.assertEqual(self.kept()["v0.1.0"], before)

    def test_deleted_upstream_tag_stays_kept(self):
        self.mirror()
        self.git(self.upstream, "tag", "-d", "v0.1.0")
        self.mirror()
        self.assertIn("v0.1.0", self.kept())

    def test_a_tag_on_a_commit_the_fork_lacks_is_reported_and_the_rest_are_copied(self):
        self.commit("four")
        self.git(self.upstream, "tag", "v0.4.0")
        copied, failures = self.mirror()
        self.assertEqual(sorted(copied), ["node-sdk/v0.1.0", "v0.1.0", "v0.2.0"])
        self.assertEqual(failures, ["v0.4.0: gh: Object does not exist (HTTP 422)"])
        self.assertNotIn("v0.4.0", self.kept())

    def test_a_tag_object_the_api_would_change_is_not_created(self):
        self.skew = True
        copied, failures = self.mirror()
        self.assertEqual(sorted(copied), ["node-sdk/v0.1.0", "v0.1.0"])
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0].startswith("v0.2.0: the API made a different tag object"))
        self.assertNotIn("v0.2.0", self.kept())

    def test_a_tag_with_extra_headers_is_not_copied(self):
        head = self.git(self.upstream, "rev-parse", "HEAD")
        content = f"object {head}\ntype commit\ntag odd\ntagger A <a@example.invalid> 1700000000 +0000\nextra x\n\nm\n"
        oid = self.git(self.upstream, "hash-object", "-t", "tag", "-w", "--literally", "--stdin", stdin=content)
        self.git(self.upstream, "update-ref", "refs/tags/odd", oid)
        copied, failures = self.mirror()
        self.assertNotIn("odd", copied)
        self.assertEqual(failures, ["odd: annotated tag the API cannot copy exactly; not created"])

    def test_tagger_zone_and_date_survive_the_api_fields(self):
        text = "object " + "a" * 40 + "\ntype commit\ntag t\ntagger A B <a@x.invalid> 1785813761 -0730\n\nbody\n\nmore\n"
        fields = tags.tag_fields(text)
        self.assertEqual(fields["tagger"], {"name": "A B", "email": "a@x.invalid", "date": "2026-08-03T19:52:41-07:30"})
        self.assertEqual(fields["message"], "body\n\nmore\n")

    def test_unsupported_names_are_reported_not_copied(self):
        to_copy, conflicts = tags.plan({"v1": "a" * 40, "-x": "b" * 40, "a..b": "c" * 40, "x.lock": "d" * 40}, {})
        self.assertEqual(to_copy, {"v1": "a" * 40})
        self.assertEqual(len(conflicts), 3)


if __name__ == "__main__":
    unittest.main()
