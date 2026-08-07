"""Every dirty case here was observed in a real SCA_Worksheet_data export."""

from __future__ import annotations

import pytest

from nexus_autofix.appsec.sheet import (
    Gav,
    SheetError,
    dedupe,
    for_repo,
    narrow_to_group,
    parse_filename,
    parse_topfix,
    read_rows,
)

ALL_HEADERS = [
    "GITHUB_ORG", "GITHUB_REPO_NAME", "LIBRARY_NAME", "LIBRARY_FILENAME",
    "VULN_TOPFIX_RESOLUTION", "LIBRARY_TYPE", "VULN_NAME", "DIRECT_DEPENDENCY", "CVSS3 Score",
]


def _workbook(tmp_path, headers, rows, name="sca.xlsx"):
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "SCA_Worksheet_data"
    sheet.append(headers)
    for row in rows:
        sheet.append(row)
    path = tmp_path / name
    book.save(path)
    return path


def _row(org="cardissuer-customerprofile-org", repo="ac-registration-app", name="Bouncy Castle Provider",
         filename="bcprov-jdk15on-1.49.jar", topfix="org.bouncycastle:bcprov-jdk15on:1.64",
         lib_type="Java", vuln="CVE-2016-1000352", direct="FALSE", cvss=7.5):
    return [org, repo, name, filename, topfix, lib_type, vuln, direct, cvss]


# --- filenames ------------------------------------------------------------------------

@pytest.mark.parametrize("filename,expected", [
    ("bcprov-jdk15on-1.49.jar", ("bcprov-jdk15on", "1.49")),
    ("hsqldb-1.8.0.10.jar", ("hsqldb", "1.8.0.10")),
    ("jackson-core-2.18.6.jar", ("jackson-core", "2.18.6")),
    ("neethi-3.2.2.jar", ("neethi", "3.2.2")),
    ("xalan-2.7.2.jar", ("xalan", "2.7.2")),
    ("jdom-1.1.3.jar", ("jdom", "1.1.3")),
    ("bcprov-jdk18on-1.84.jar", ("bcprov-jdk18on", "1.84")),
])
def test_parse_filename_splits_artifact_from_version(filename, expected):
    assert parse_filename(filename) == expected


def test_parse_filename_refuses_a_revision_that_is_not_a_version():
    # jtidy-r938.jar: "r938" is a revision. Guessing a version here would let a later
    # upgrade check compare against something meaningless.
    assert parse_filename("jtidy-r938.jar") is None


def test_parse_filename_handles_a_missing_extension():
    assert parse_filename("bcprov-jdk15on-1.49") == ("bcprov-jdk15on", "1.49")


# --- the topfix column ----------------------------------------------------------------

def test_parse_topfix_reads_a_single_clean_gav():
    usable, discarded = parse_topfix("xalan:xalan:2.7.3")
    assert usable == [Gav("xalan", "xalan", "2.7.3")]
    assert discarded == []


def test_parse_topfix_accepts_comma_semicolon_and_space_separators():
    usable, _ = parse_topfix(
        "org.bouncycastle:bc-fips:1.0.2;org.bouncycastle:bcprov-jdk15on:1.60, "
        "org.bouncycastle:bcprov-jdk18on:1.78"
    )
    assert [g.version for g in usable] == ["1.0.2", "1.60", "1.78"]


def test_parse_topfix_reads_the_space_dash_version_separator():
    # "group:artifact - version", with an underscore in the version.
    usable, discarded = parse_topfix(
        "org.apache.servicemix.bundles:org.apache.servicemix.bundles.jdom - 2.0.5_1"
    )
    assert usable == [Gav("org.apache.servicemix.bundles", "org.apache.servicemix.bundles.jdom", "2.0.5_1")]
    assert discarded == []


@pytest.mark.parametrize("junk", [
    "1.56",                                                  # a bare version, stored as a number
    "BouncyCastle.Cryptography",                             # a .NET package
    "https://github.com/org/repo",                           # an embedded URL
    "jmeter - no_fix",                                       # an explicit non-answer
    "techdivision/techdivision_magentounittesting - no_fix",
])
def test_parse_topfix_discards_junk_but_reports_it(junk):
    usable, discarded = parse_topfix(f"xalan:xalan:2.7.3,{junk}")
    assert usable == [Gav("xalan", "xalan", "2.7.3")]
    assert discarded == [junk]


def test_parse_topfix_handles_a_numeric_cell():
    # Excel stores a bare "1.56" as a float; str.strip() on it would raise.
    usable, discarded = parse_topfix(1.56)
    assert usable == []
    assert discarded == ["1.56"]


def test_parse_topfix_of_a_blank_cell_is_empty():
    assert parse_topfix(None) == ([], [])
    assert parse_topfix("   ") == ([], [])


# --- reading the workbook -------------------------------------------------------------

def test_read_rows_reads_a_simple_sheet(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [_row()])
    rows, stats = read_rows(path)

    assert stats.rows_total == 1 and stats.rows_kept == 1
    assert rows[0].artifact_id == "bcprov-jdk15on"
    assert rows[0].current_version == "1.49"
    assert rows[0].direct is False
    assert rows[0].cvss3 == 7.5


def test_column_order_does_not_matter(tmp_path):
    # The export's column ORDER is not stable; only the header names are. Position must
    # never be assumed.
    shuffled = ["CVSS3 Score", "LIBRARY_FILENAME", "VULN_NAME", "GITHUB_REPO_NAME",
                "VULN_TOPFIX_RESOLUTION", "DIRECT_DEPENDENCY", "GITHUB_ORG",
                "LIBRARY_TYPE", "LIBRARY_NAME"]
    path = _workbook(tmp_path, shuffled, [[
        7.5, "bcprov-jdk15on-1.49.jar", "CVE-2016-1000352", "ac-registration-app",
        "org.bouncycastle:bcprov-jdk15on:1.64", "FALSE", "cardissuer-customerprofile-org",
        "Java", "Bouncy Castle Provider",
    ]])
    rows, _ = read_rows(path)

    assert rows[0].github_org == "cardissuer-customerprofile-org"
    assert rows[0].github_repo_name == "ac-registration-app"
    assert rows[0].artifact_id == "bcprov-jdk15on"
    assert rows[0].cvss3 == 7.5


def test_headers_match_regardless_of_case_and_separators(tmp_path):
    headers = ["github org", "Github_Repo_Name", "library  filename", "vuln_topfix_resolution"]
    path = _workbook(tmp_path, headers, [[
        "cardissuer-customerprofile-org", "ac-registration-app",
        "xalan-2.7.2.jar", "xalan:xalan:2.7.3",
    ]])
    rows, _ = read_rows(path)
    assert rows[0].artifact_id == "xalan"


def test_optional_columns_may_be_absent(tmp_path):
    headers = ["GITHUB_ORG", "GITHUB_REPO_NAME", "LIBRARY_FILENAME", "VULN_TOPFIX_RESOLUTION"]
    path = _workbook(tmp_path, headers, [[
        "org", "repo", "xalan-2.7.2.jar", "xalan:xalan:2.7.3",
    ]])
    rows, _ = read_rows(path)
    assert rows[0].direct is None and rows[0].cvss3 is None and rows[0].library_type == ""


def test_a_missing_required_column_names_what_was_found(tmp_path):
    path = _workbook(tmp_path, ["GITHUB_ORG", "LIBRARY_FILENAME"], [["org", "x-1.0.jar"]])
    with pytest.raises(SheetError) as exc:
        read_rows(path)

    message = str(exc.value)
    assert "github_repo_name" in message
    assert "Headers found" in message and "github org" in message


def test_rows_without_a_repo_or_filename_are_counted_not_dropped_silently(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(),
        _row(org=""),
        _row(filename=""),
        _row(filename="jtidy-r938.jar"),
    ])
    rows, stats = read_rows(path)

    assert stats.rows_total == 4 and stats.rows_kept == 1
    assert stats.skipped_missing_repo == 1
    assert stats.skipped_missing_filename == 1
    assert stats.skipped_unparsable_filename == ["jtidy-r938.jar"]
    assert len(rows) == 1


def test_rows_for_another_ecosystem_are_skipped(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [_row(), _row(lib_type="JavaScript")])
    rows, stats = read_rows(path, library_type="Java")

    assert stats.rows_kept == 1 and stats.skipped_wrong_type == 1
    assert len(rows) == 1


def test_an_empty_workbook_is_a_clear_error(tmp_path):
    import openpyxl

    book = openpyxl.Workbook()
    path = tmp_path / "empty.xlsx"
    book.save(path)
    with pytest.raises(SheetError):
        read_rows(path)


# --- dedupe ---------------------------------------------------------------------------

def test_dedupe_folds_per_cve_rows_into_one_library(tmp_path):
    # The real export repeats a library once per CVE, each row suggesting a different fix.
    # Only bcprov-jdk15on:1.64 names the artifact actually installed; the rest are
    # migrations to a different artifact.
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(vuln="CVE-2016-1", topfix="org.bouncycastle:bcprov-debug-jdk15on:1.56"),
        _row(vuln="CVE-2018-2", topfix="org.bouncycastle:bcprov-jdk15on:1.60"),
        _row(vuln="CVE-2019-3", topfix="org.bouncycastle:bc-fips:1.0.2"),
        _row(vuln="CVE-2024-4", topfix="org.bouncycastle:bcprov-jdk15on:1.64"),
    ])
    rows, _ = read_rows(path)
    libraries = dedupe(rows)

    assert len(libraries) == 1
    library = libraries[0]
    assert library.current_version == "1.49"
    # The HIGHEST same-artifact candidate, not the first or the last.
    assert library.sheet_version == "1.64"
    assert library.group_id == "org.bouncycastle"
    assert library.cve_ids == ("CVE-2016-1", "CVE-2018-2", "CVE-2019-3", "CVE-2024-4")
    assert {g.artifact_id for g in library.swap_candidates} == {"bcprov-debug-jdk15on", "bc-fips"}


def test_dedupe_keeps_different_libraries_apart(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(),
        _row(name="Xalan Java", filename="xalan-2.7.2.jar", topfix="xalan:xalan:2.7.3"),
    ])
    libraries = dedupe(read_rows(path)[0])
    assert {lib.artifact_id for lib in libraries} == {"bcprov-jdk15on", "xalan"}


def test_a_library_with_only_swap_candidates_has_no_sheet_version(tmp_path):
    # Every suggestion is a migration to another artifact. There is no version bump to make.
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(topfix="org.bouncycastle:bc-fips:2.1.3,org.bouncycastle:bcprov-lts8on:2.73.12"),
    ])
    library = dedupe(read_rows(path)[0])[0]

    assert library.sheet_version is None
    assert library.group_id is None
    assert len(library.swap_candidates) == 2


def test_dedupe_collects_discarded_tokens_across_rows(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(vuln="CVE-1", topfix="org.bouncycastle:bcprov-jdk15on:1.64,BouncyCastle.Cryptography"),
        _row(vuln="CVE-2", topfix="jmeter - no_fix"),
    ])
    library = dedupe(read_rows(path)[0])[0]
    assert set(library.topfix_discarded) == {"BouncyCastle.Cryptography", "jmeter - no_fix"}


def test_a_matching_artifact_under_a_different_group_is_not_a_bump(tmp_path):
    """The subtle one: same artifactId, different package.

    "com.fasterxml.jackson.core:jackson-core" and "tools.jackson.core:jackson-core" share
    an artifact name and are different packages. Taking the higher version across both
    would switch the group id — a migration wearing a matching artifact name. Since
    LIBRARY_FILENAME never states a group, nothing here can tell which is installed.
    """
    path = _workbook(tmp_path, ALL_HEADERS, [_row(
        name="Jackson-core", filename="jackson-core-2.18.6.jar",
        topfix="com.fasterxml.jackson.core:jackson-core:2.18.8,tools.jackson.core:jackson-core:3.1.4",
    )])
    library = dedupe(read_rows(path)[0])[0]

    assert library.sheet_version is None
    assert library.group_id is None
    assert {g.group_id for g in library.ambiguous_candidates} == {
        "com.fasterxml.jackson.core", "tools.jackson.core",
    }


def test_one_group_across_several_rows_is_not_ambiguous(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(vuln="CVE-1", topfix="org.bouncycastle:bcprov-jdk15on:1.60"),
        _row(vuln="CVE-2", topfix="org.bouncycastle:bcprov-jdk15on:1.64"),
    ])
    library = dedupe(read_rows(path)[0])[0]

    assert library.ambiguous_candidates == ()
    assert library.sheet_version == "1.64"


def test_narrow_to_group_settles_an_ambiguous_library(tmp_path):
    # Nexus IQ's report states the installed groupId, which the sheet never does.
    path = _workbook(tmp_path, ALL_HEADERS, [_row(
        filename="jackson-core-2.18.6.jar",
        topfix="com.fasterxml.jackson.core:jackson-core:2.18.8,tools.jackson.core:jackson-core:3.1.4",
    )])
    library = narrow_to_group(dedupe(read_rows(path)[0])[0], "com.fasterxml.jackson.core")

    assert library.sheet_version == "2.18.8"
    assert library.group_id == "com.fasterxml.jackson.core"
    assert library.ambiguous_candidates == ()
    # The rejected group is a migration, and is kept as one.
    assert [str(g) for g in library.swap_candidates] == ["tools.jackson.core:jackson-core:3.1.4"]


def test_narrow_to_group_makes_everything_a_swap_when_no_group_matches(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [_row(
        filename="jackson-core-2.18.6.jar",
        topfix="com.fasterxml.jackson.core:jackson-core:2.18.8,tools.jackson.core:jackson-core:3.1.4",
    )])
    library = narrow_to_group(dedupe(read_rows(path)[0])[0], "org.somewhere.else")

    assert library.sheet_version is None
    assert library.ambiguous_candidates == ()
    assert len(library.swap_candidates) == 2


def test_narrow_to_group_is_a_no_op_for_an_unambiguous_library(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [_row()])
    library = dedupe(read_rows(path)[0])[0]
    assert narrow_to_group(library, "org.bouncycastle") is library


def test_for_repo_matches_case_insensitively(tmp_path):
    path = _workbook(tmp_path, ALL_HEADERS, [
        _row(),
        _row(repo="some-other-app", filename="xalan-2.7.2.jar"),
    ])
    libraries = dedupe(read_rows(path)[0])

    matched = for_repo(libraries, "CardIssuer-CustomerProfile-Org", "AC-Registration-App")
    assert len(matched) == 1
    assert matched[0].artifact_id == "bcprov-jdk15on"
