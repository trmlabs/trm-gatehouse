#!/usr/bin/env python3
"""Keep every upstream release tag in this fork under upstream/; never move or delete one."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

UPSTREAM = "https://github.com/Infisical/agent-vault.git"
PREFIX = "refs/tags/upstream/"
TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*")
TAGGER = re.compile(r"(?P<name>.+) <(?P<email>[^<>]*)> (?P<when>\d+) (?P<sign>[+-])(?P<hours>\d\d)(?P<minutes>\d\d)")


def git(directory, *args, check=True):
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c",
                           "credential.helper=!gh auth git-credential", *args],
                          cwd=directory, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def refs(text, prefix):
    """Map ref name (without prefix) to object ID from ls-remote or for-each-ref output."""
    found = {}
    for line in text.splitlines():
        oid, name = line.split(None, 1)
        if name.startswith(prefix) and not name.endswith("^{}"):
            found[name[len(prefix):]] = oid
    return found


def plan(upstream, mirrored):
    """Return (to_push, conflicts): new tags to copy, and tags upstream moved."""
    to_push, conflicts = {}, []
    for name, oid in sorted(upstream.items()):
        if not TAG_NAME.fullmatch(name) or ".." in name or name.endswith(".lock"):
            conflicts.append(f"{name}: unsupported tag name")
        elif name not in mirrored:
            to_push[name] = oid
        elif mirrored[name] != oid:
            conflicts.append(f"{name}: upstream now points elsewhere; the kept copy is unchanged")
    return to_push, conflicts


def tag_fields(text):
    """The API fields of an unsigned annotated tag object, or None if it holds anything else."""
    head, _, message = text.partition("\n\n")
    lines = head.splitlines()
    if [line.split(" ", 1)[0] for line in lines] != ["object", "type", "tag", "tagger"]:
        return None
    tagger = TAGGER.fullmatch(lines[3].split(" ", 1)[1])
    if tagger is None:
        return None
    offset = timedelta(hours=int(tagger["hours"]), minutes=int(tagger["minutes"]))
    zone = timezone(-offset if tagger["sign"] == "-" else offset)
    return {"object": lines[0].split(" ", 1)[1], "type": lines[1].split(" ", 1)[1], "tag": lines[2].split(" ", 1)[1],
            "message": message,
            "tagger": {"name": tagger["name"], "email": tagger["email"],
                       "date": datetime.fromtimestamp(int(tagger["when"]), zone).isoformat()}}


def api(run, repository, path, payload):
    """One POST to the fork's REST API with the workflow token. Raise with GitHub's reason if refused."""
    result = run(["gh", "api", "--method", "POST", f"repos/{repository}/{path}", "--input", "-"],
                 input=json.dumps(payload), text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError((result.stderr.strip().splitlines() or ["request refused"])[-1])
    return json.loads(result.stdout)


def api_publisher(repository, run=subprocess.run):
    """Make a function that creates one kept tag in the fork through the REST API.

    A push is not used: GitHub refuses a push from the workflow token that places a tag on an
    older commit holding workflow files, because that token cannot hold the workflows permission.
    The commits are already in the fork through the upstream merges, so the API only names them.
    It never moves a tag: creating a name that exists is refused. An annotated tag's object is
    made again from its fields and used only if it has the same ID as upstream's.
    """
    def publish(directory, oid, name):
        try:
            if git(directory, "cat-file", "-t", oid).stdout.strip() == "tag":
                fields = tag_fields(git(directory, "cat-file", "tag", oid).stdout)
                if fields is None:
                    return "annotated tag the API cannot copy exactly; not created"
                if api(run, repository, "git/tags", fields)["sha"] != oid:
                    return "the API made a different tag object than upstream's; not created"
            api(run, repository, "git/refs", {"ref": PREFIX + name, "sha": oid})
        except RuntimeError as error:
            return str(error)
        except (subprocess.CalledProcessError, UnicodeDecodeError):
            return "the tag could not be read; not created"
        return None
    return publish


def mirror(directory, origin, publish, upstream_url=UPSTREAM):
    """Copy missing upstream tags to origin with publish(directory, oid, name). Return (copied, failures)."""
    git(directory, "fetch", "--no-tags", upstream_url, "+refs/tags/*:refs/upstream-tags/*")
    upstream = refs(git(directory, "for-each-ref", "--format=%(objectname) %(refname)",
                        "refs/upstream-tags/").stdout, "refs/upstream-tags/")
    mirrored = refs(git(directory, "ls-remote", origin, PREFIX + "*").stdout, PREFIX)
    to_copy, failures = plan(upstream, mirrored)
    copied = []
    # One request per tag, so one refused tag does not hold back the rest.
    for name, oid in to_copy.items():
        reason = publish(directory, oid, name)
        if reason:
            failures.append(f"{name}: {reason}")
        else:
            copied.append(name)
    return copied, failures


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or repository.lower() == "infisical/agent-vault":
        raise RuntimeError("Expected a downstream repository")
    # Ignore machine-level Git filters and hooks. Only fixed Git operations run.
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    os.environ["GIT_CONFIG_GLOBAL"] = "/dev/null"
    origin = f"https://github.com/{repository}.git"
    with tempfile.TemporaryDirectory(prefix="upstream-tags-") as temp:
        git(temp, "init", "--bare", "-q")
        copied, failures = mirror(temp, origin, api_publisher(repository))
    # The reasons go to the job log as well as the summary, so a failed run explains itself.
    for line in failures:
        print(f"Not copied: {line}", file=sys.stderr)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as f:
        f.write(f"Copied {len(copied)} upstream tag(s) under `upstream/`.\n\n")
        for name in copied:
            f.write(f"- `upstream/{name}`\n")
        if failures:
            f.write("\nNot copied:\n\n")
            for line in failures:
                f.write(f"- {line}\n")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
