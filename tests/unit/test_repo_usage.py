import json

from nexus_autofix.repo.usage import find_usage


def _npm_repo(tmp_path, *, deps=None, files=None):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": deps or {}}), encoding="utf-8"
    )
    for name, body in (files or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def test_a_declared_and_imported_package_is_found_in_both_places(tmp_path):
    _npm_repo(
        tmp_path, deps={"lodash": "^4.17.20"},
        files={"src/app.js": "import _ from 'lodash';\nexport const x = _.chunk([1]);\n"},
    )

    evidence = find_usage("lodash", tmp_path, "yarn")

    assert [r.path for r in evidence.declared_in_manifest] == ["package.json"]
    assert [r.path for r in evidence.referenced_in_source] == ["src/app.js"]
    assert "declared in the manifest and referenced" in evidence.summary


def test_a_require_call_counts_as_a_reference(tmp_path):
    _npm_repo(tmp_path, deps={"axios": "1.6.0"},
              files={"src/http.js": "const axios = require('axios');\n"})

    assert find_usage("axios", tmp_path, "npm").referenced_in_source


def test_a_subpath_import_still_matches_the_package(tmp_path):
    """`import x from 'lodash/chunk'` uses lodash."""
    _npm_repo(tmp_path, deps={"lodash": "1.0.0"},
              files={"src/a.ts": "import chunk from 'lodash/chunk';\n"})

    assert find_usage("lodash", tmp_path, "npm").referenced_in_source


def test_a_declared_but_unreferenced_package_says_so_without_recommending_removal(tmp_path):
    """The dangerous direction: a package can be loaded by name at runtime."""
    _npm_repo(tmp_path, deps={"left-pad": "1.3.0"},
              files={"src/app.js": "export const x = 1;\n"})

    evidence = find_usage("left-pad", tmp_path, "yarn")

    assert evidence.declared_in_manifest
    assert not evidence.referenced_in_source
    assert "hint and nothing more" in evidence.summary
    assert "remove" not in evidence.summary.lower()


def test_a_transitive_package_is_reported_as_not_removable_here(tmp_path):
    """Referenced but not declared: the manifest does not ask for it, so the change
    belongs to whatever does."""
    _npm_repo(tmp_path, deps={"parent-pkg": "1.0.0"},
              files={"src/a.js": "import x from 'brace-expansion';\n"})

    evidence = find_usage("brace-expansion", tmp_path, "npm")

    assert not evidence.declared_in_manifest
    assert evidence.referenced_in_source
    assert "cannot be removed here directly" in evidence.summary


def test_nothing_found_is_reported_as_nothing_found_not_as_unused(tmp_path):
    """The whole point. A transitive dependency is used by its parent, not by this code,
    so 'no references' is the expected result for one and says nothing about safety."""
    _npm_repo(tmp_path, deps={}, files={"src/a.js": "export const x = 1;\n"})

    evidence = find_usage("some-transitive", tmp_path, "yarn")

    assert not evidence.any_reference
    assert "does NOT establish that it is unused" in evidence.summary


def test_a_config_file_reference_is_counted(tmp_path):
    """A babel plugin or webpack loader is used without ever being imported — missing
    these is the likeliest way to call something load-bearing unused."""
    _npm_repo(tmp_path, deps={"babel-plugin-macros": "3.0.0"})
    (tmp_path / ".babelrc").write_text(
        json.dumps({"plugins": ["babel-plugin-macros"]}), encoding="utf-8"
    )

    evidence = find_usage("babel-plugin-macros", tmp_path, "npm")

    assert [r.path for r in evidence.referenced_in_config] == [".babelrc"]
    assert evidence.any_reference


def test_node_modules_and_build_output_are_not_searched(tmp_path):
    """Every package appears inside node_modules, which would make everything look used."""
    _npm_repo(tmp_path, deps={})
    vendored = tmp_path / "node_modules" / "left-pad"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("require('left-pad')\n", encoding="utf-8")
    built = tmp_path / "dist"
    built.mkdir()
    (built / "bundle.js").write_text("require('left-pad')\n", encoding="utf-8")

    assert find_usage("left-pad", tmp_path, "npm").any_reference is False


def test_a_bare_name_in_prose_is_not_counted_as_a_reference(tmp_path):
    """Matching the bare name would make "core" or "common" appear used everywhere."""
    _npm_repo(tmp_path, deps={},
              files={"src/a.js": "// core is a nice word\nconst core = 1;\n"})

    assert find_usage("core", tmp_path, "npm").any_reference is False


def test_a_maven_coordinate_matches_its_import_package(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency>"
        "<groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>"
        "</dependency></dependencies></project>", encoding="utf-8",
    )
    src = tmp_path / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "A.java").write_text(
        "import org.apache.commons.text.StringSubstitutor;\nclass A {}\n", encoding="utf-8"
    )

    evidence = find_usage("commons-text", tmp_path, "maven")

    assert evidence.declared_in_manifest
    assert evidence.referenced_in_source


def test_a_gradle_declaration_is_found(tmp_path):
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n  implementation 'io.netty:netty-codec-http:4.1.100.Final'\n}\n",
        encoding="utf-8",
    )

    evidence = find_usage("netty-codec-http", tmp_path, "gradle")

    assert [r.path for r in evidence.declared_in_manifest] == ["build.gradle"]


def test_an_empty_component_name_matches_nothing(tmp_path):
    _npm_repo(tmp_path, deps={"a": "1"})

    assert find_usage("   ", tmp_path, "npm").any_reference is False


def test_no_summary_ever_recommends_removal(tmp_path):
    """Structural guard: this module reports evidence and must never render a verdict."""
    _npm_repo(tmp_path, deps={"left-pad": "1.3.0"},
              files={"src/a.js": "import x from 'left-pad';\n"})

    for component in ("left-pad", "absent-pkg"):
        summary = find_usage(component, tmp_path, "npm").summary.lower()
        for phrase in ("safe to remove", "can be removed", "unused dependency", "delete"):
            assert phrase not in summary, f"{component}: summary renders a verdict"
