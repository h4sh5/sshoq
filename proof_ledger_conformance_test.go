package ssh3

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The ledger is machine-checked.
//
// `proof/SECURITY_REQUIREMENTS.md` is where every coverage claim in this project is written down, and it
// is maintained by hand. Three different ways for it to go wrong have already happened: a promise living
// in a comment above a constant that no row recorded (**F8**), a row claiming "covered by unit tests" for
// a function no test called (**F9**), and a row whose status understated the proof beside it because the
// row had not been re-read since the model changed. All three are the same failure -- the table and the
// artefacts drift -- and all three are mechanical, so they are now checked mechanically, on every
// `make proof-conformance`, by this file.
//
// What is checked is the *consistency* of the ledger with the repository, never the soundness of a
// proof: no test here can tell you a spec was wrong. What it can tell you is that a row points at a file
// that no longer exists, cites a test that was renamed, counts a status nobody assigned, or references a
// finding that was never written up. The last is not hypothetical: `F10` was named in three places in this
// directory and had never had a section, which is what the equivalent queries turned up when they were
// rehearsed in a shell before being written down here as a test.

// conformanceCatalogue and conformanceReadme are the two documents. Their paths are relative to the
// repository root, which is where `go test` runs a package's tests.
var (
	conformanceCatalogue = filepath.Join("proof", "SECURITY_REQUIREMENTS.md")
	conformanceReadme    = filepath.Join("proof", "README.md")
)

// conformanceStatusTokens are the seven labels a row's status cell must begin with. A new label means a
// new kind of claim, and both the matrix in proof/README.md and this list have to be told about it.
var conformanceStatusTokens = map[string]bool{
	"proved:model": true, "proved:shipped": true, "conformant": true,
	"partial": true, "out-of-scope": true, "open": true, "phase-4": true,
}

// conformanceRows parses the catalogue's requirement rows: ID, requirement text, code, status.
func conformanceRows(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	rows := [][]string{}
	for i, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "| SR-") {
			continue
		}
		cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"), "|")
		if len(cells) != 4 {
			t.Errorf("%s:%d: requirement row has %d cells, want 4: %.80s", path, i+1, len(cells), line)
			continue
		}
		for j := range cells {
			cells[j] = strings.TrimSpace(cells[j])
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("%s contains no requirement rows", path)
	}
	return rows
}

// conformanceRepoFiles walks the repository once, skipping the vendored toolchains, and returns every
// file path and, for lookups by bare name, the directories each base name appears in.
func conformanceRepoFiles(t *testing.T) []string {
	t.Helper()
	var all []string
	byBase := map[string][]string{}
	skip := map[string]bool{".git": true, ".gomodcache": true, ".gotoolchain": true, ".proof-tools": true}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		all = append(all, path)
		byBase[info.Name()] = append(byBase[info.Name()], path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	_ = byBase
	return all
}

// TestConformanceCatalogueRowShape checks the rows are rows: one per requirement, four cells, an ID from a
// category the document defines, no identifier used twice. A row that lost its final pipe stops being a
// row and starts being a paragraph, which has happened while editing a long status cell.
func TestConformanceCatalogueRowShape(t *testing.T) {
	rows := conformanceRows(t, conformanceCatalogue)
	seen := map[string]int{}
	// The categories are a closed set on purpose: a new one is a statement that the catalogue has
	// grown a subject, which is a decision someone notices rather than a typo in a row. SR-DAC joined
	// when the SFTP server's file-access decision was split out into sftp/dac_rules.go and proved.
	id := regexp.MustCompile(`^SR-(AUTH|PERM|TR|RES|PARSE|DAC)-[0-9]{2}$`)
	for _, r := range rows {
		if !id.MatchString(r[0]) {
			t.Errorf("requirement id %q is not SR-{AUTH,PERM,TR,RES,PARSE,DAC}-NN", r[0])
		}
		seen[r[0]]++
		if r[1] == "" || r[2] == "" || r[3] == "" {
			t.Errorf("%s: a row cell is empty", r[0])
		}
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("%s appears in %d rows", k, n)
		}
	}
	if len(rows) < 30 {
		t.Fatalf("only %d requirement rows; the catalogue is smaller than the programme", len(rows))
	}
	t.Logf("%d rows, %d identifiers", len(rows), len(seen))
}

// TestConformanceCatalogueStatusesMatchTheMatrix is the count check: every row must begin its status cell
// with one of the seven tokens, and the tallies must be the numbers printed in proof/README.md. The
// matrix is the sentence a reader trusts about coverage; this makes it a derived quantity.
func TestConformanceCatalogueStatusesMatchTheMatrix(t *testing.T) {
	rows := conformanceRows(t, conformanceCatalogue)
	token := regexp.MustCompile(`^\*\*\[([\w:-]+)\]\*\*`)
	counts := map[string]int{}
	for _, r := range rows {
		m := token.FindStringSubmatch(r[3])
		if m == nil {
			t.Errorf("%s: status cell does not begin with a **[token]**: %.70s", r[0], r[3])
			continue
		}
		if !conformanceStatusTokens[m[1]] {
			t.Errorf("%s: unknown status token %q", r[0], m[1])
			continue
		}
		counts[m[1]]++
	}

	readme, err := os.ReadFile(conformanceReadme)
	if err != nil {
		t.Fatalf("cannot read %s: %v", conformanceReadme, err)
	}
	matrixRow := regexp.MustCompile("(?m)^\\| `([\\w:-]+)`[^|]*\\| ([0-9]+) \\|")
	claimed := map[string]int{}
	for _, m := range matrixRow.FindAllStringSubmatch(string(readme), -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Errorf("matrix count %q: %v", m[2], err)
			continue
		}
		claimed[m[1]] = n
	}
	if len(claimed) == 0 {
		t.Fatalf("no status matrix found in %s -- the row format this test reads changed", conformanceReadme)
	}
	total := 0
	for tok, n := range claimed {
		total += n
		if counts[tok] != n {
			t.Errorf("%s: the matrix says %d rows, the catalogue has %d", tok, n, counts[tok])
		}
	}
	if total != len(rows) {
		t.Errorf("the matrix adds up to %d rows, the catalogue has %d", total, len(rows))
	}
	if !t.Failed() {
		t.Logf("matrix and catalogue agree on %d rows over %d tokens", total, len(claimed))
	}
}

// TestConformanceCatalogueNamesExist is the check **F9** asks for, applied to everything the documents
// cite rather than to one function: every `.go` file, every `Test...` identifier, every
// `proof/<unit>/model.gobra` and every `*_conformance_test.go` mentioned in the catalogue or the README
// has to exist in the tree. A row is an argument, and an argument that cites a renamed test is not one.
func TestConformanceCatalogueNamesExist(t *testing.T) {
	all := conformanceRepoFiles(t)
	docs := ""
	for _, p := range []string{conformanceCatalogue, conformanceReadme} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("cannot read %s: %v", p, err)
		}
		docs += string(data) + "\n"
	}

	goFiles := map[string]bool{}
	for _, p := range all {
		if strings.HasSuffix(p, ".go") {
			goFiles[filepath.Base(p)] = true
		}
	}
	for _, name := range uniqueMatches(regexp.MustCompile("`([\\w./-]+\\.go)`"), docs) {
		base := filepath.Base(name)
		if !goFiles[base] {
			t.Errorf("a document cites %s, which is not in the tree", name)
		}
	}

	// Test identifiers, excluding the prose placeholder "TestConformance..." used in headings.
	definedTests := map[string]bool{}
	for _, p := range all {
		if !strings.HasSuffix(p, "_test.go") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("cannot read %s: %v", p, err)
			continue
		}
		for _, m := range regexp.MustCompile(`func (Test\w+)`).FindAllStringSubmatch(string(data), -1) {
			definedTests[m[1]] = true
		}
	}
	for _, name := range uniqueMatches(regexp.MustCompile(`\b(Test(?:Conformance)?[A-Z]\w{3,})\b`), docs) {
		if name == "TestConformance" {
			continue
		}
		if !definedTests[name] {
			t.Errorf("a document cites %s, which no *_test.go defines", name)
		}
	}

	for _, unit := range uniqueMatches(regexp.MustCompile("proof/([\\w-]+)/model\\.gobra"), docs) {
		if _, err := os.Stat(filepath.Join("proof", unit, "model.gobra")); err != nil {
			t.Errorf("a document cites proof/%s/model.gobra, which does not exist", unit)
		}
	}

	// The other direction too, for evidence files: conformance tests nobody cites are evidence that has
	// fallen out of the argument.
	cited := map[string]bool{}
	for _, p := range all {
		if strings.Contains(filepath.Base(p), "_conformance_test.go") {
			base := filepath.Base(p)
			cited[base] = strings.Contains(docs, base)
		}
	}
	for name, ok := range cited {
		if !ok {
			t.Errorf("%s runs in make proof-conformance but no document cites it", name)
		}
	}
	if len(cited) < 10 {
		t.Errorf("only %d conformance test files in the tree", len(cited))
	}
	t.Logf("%d go files, %d tests defined, %d conformance files cited", len(goFiles), len(definedTests), len(cited))
}

// TestConformanceFindingsAreWrittenUp keeps `F<digit>` honest in both directions: a reference must resolve
// to a section, and a section must be referenced, because an orphan finding is a lesson nobody is told.
func TestConformanceFindingsAreWrittenUp(t *testing.T) {
	data, err := os.ReadFile(conformanceCatalogue)
	if err != nil {
		t.Fatalf("cannot read %s: %v", conformanceCatalogue, err)
	}
	catalogue := string(data)
	readme, err := os.ReadFile(conformanceReadme)
	if err != nil {
		t.Fatalf("cannot read %s: %v", conformanceReadme, err)
	}
	sections := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^### (F[0-9]+)").FindAllStringSubmatch(catalogue, -1) {
		sections[m[1]] = true
	}
	allDocs := catalogue + "\n" + string(readme)
	referenced := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bF([0-9]+)\b`).FindAllStringSubmatch(allDocs, -1) {
		referenced["F"+m[1]] = true
	}
	for f := range referenced {
		if !sections[f] {
			t.Errorf("%s is referenced but has no section in %s", f, conformanceCatalogue)
		}
	}
	for f := range sections {
		if !referenced[f] {
			t.Errorf("%s has a section but is never referenced", f)
		}
	}
	if len(sections) < 5 {
		t.Errorf("only %d finding sections; the catalogue documents fewer than it has", len(sections))
	}
	t.Logf("%d findings, all referenced and all written up", len(sections))
}

// TestConformanceModelUnitsAreCatalogued stops a Gobra unit from being verified and unaccounted for: every
// directory under proof/ with a model.gobra must be named by a row, and every model unit a document names
// must exist (checked in TestConformanceCatalogueNamesExist).
func TestConformanceModelUnitsAreCatalogued(t *testing.T) {
	dirs, err := os.ReadDir("proof")
	if err != nil {
		t.Fatalf("cannot read proof/: %v", err)
	}
	data, err := os.ReadFile(conformanceCatalogue)
	if err != nil {
		t.Fatalf("cannot read %s: %v", conformanceCatalogue, err)
	}
	readme, err := os.ReadFile(conformanceReadme)
	if err != nil {
		t.Fatalf("cannot read %s: %v", conformanceReadme, err)
	}
	docs := string(data) + "\n" + string(readme)
	units := []string{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		path := filepath.Join("proof", d.Name(), "model.gobra")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		units = append(units, d.Name())
		if !strings.Contains(docs, d.Name()) {
			t.Errorf("%s is verified by make proof but no document mentions %q", path, d.Name())
		}
	}
	sort.Strings(units)
	if len(units) < 10 {
		t.Errorf("only %d model units under proof/: %v", len(units), units)
	}
	t.Logf("%d model units, all catalogued: %s", len(units), strings.Join(units, ", "))
}

func uniqueMatches(re *regexp.Regexp, s string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// conformanceInPlaceUnits reads the list of shipped files that carry their own specs out of
// scripts/run-proofs.sh. They are listed, not discovered, because a file belongs to the proof when its
// specs do; this test is what makes that choice safe in both directions.
func conformanceInPlaceUnits(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("scripts", "run-proofs.sh"))
	if err != nil {
		t.Fatalf("reading the proof runner: %v", err)
	}
	block := ""
	if start := strings.Index(string(data), "INPLACE_UNITS=("); start >= 0 {
		rest := string(data)[start:]
		if end := strings.Index(rest, "\n)"); end >= 0 {
			block = rest[:end]
		}
	}
	if block == "" {
		t.Fatal("scripts/run-proofs.sh no longer has an INPLACE_UNITS list; this test has to be told where the list lives")
	}
	var units []string
	for _, m := range regexp.MustCompile(`"\$REPO_ROOT/([^"]+)"`).FindAllStringSubmatch(block, -1) {
		units = append(units, m[1])
	}
	sort.Strings(units)
	return units
}

// TestConformanceEveryInPlaceUnitIsAnnotated is the guard against the failure this programme was closest
// to repeating: a shipped file listed in INPLACE_UNITS, `make proof` reporting OK for it, and the ledger
// counting that as a proof of a requirement -- while the file contained no annotation at all. Gobra is
// happy to verify a package that specifies nothing; the verdict is then about nothing, and nothing in the
// output says so.
//
// It checks the other direction too. A file whose specs are no longer run is worse than a file with no
// specs, because the specs still read like a contract and still get edited, and the day they drift from
// the code nobody is told.
func TestConformanceEveryInPlaceUnitIsAnnotated(t *testing.T) {
	units := conformanceInPlaceUnits(t)

	annotated := map[string]int{}
	for _, path := range conformanceRepoFiles(t) {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		n := 0
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "// @ ensures"),
				strings.HasPrefix(line, "// @ requires"),
				strings.HasPrefix(line, "// @ pure"),
				strings.HasPrefix(line, "// @ invariant"):
				n++
			}
		}
		if n > 0 {
			annotated[path] = n
		}
	}

	for _, unit := range units {
		n, ok := annotated[unit]
		if !ok {
			t.Errorf("%s is listed as a proof unit and carries no @-annotation: `make proof` says OK about it, and that says nothing", unit)
			continue
		}
		if n < 2 {
			t.Errorf("%s carries a single annotation; a contract one clause deep proves almost nothing and reads like more", unit)
		}
	}

	for path, n := range annotated {
		found := false
		for _, unit := range units {
			if unit == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s carries %d annotations but is not in INPLACE_UNITS: its specs are never checked and will silently rot", path, n)
		}
	}

	t.Logf("%d shipped files carry their own specs, every one of them checked", len(units))
}

// TestConformanceProvedOnShippedRowsNameAnnotatedFiles goes one step further and ties the *claim* to the
// annotation: a row whose status says the decision is proved on the code that ships has to name a file
// that actually carries specs. Without this, the ledger can be true about a proof and about a file and
// still be false about the two being the same thing.
func TestConformanceProvedOnShippedRowsNameAnnotatedFiles(t *testing.T) {
	units := map[string]bool{}
	for _, u := range conformanceInPlaceUnits(t) {
		units[u] = true
	}

	checked := 0
	for _, row := range conformanceRows(t, conformanceCatalogue) {
		if len(row) < 4 {
			continue
		}
		id, code, status := row[0], row[2], row[3]
		if !strings.Contains(status, "proved:shipped") {
			continue
		}
		checked++
		ok := false
		for _, m := range regexp.MustCompile("`([^`]+\\.go)`").FindAllStringSubmatch(code, -1) {
			if units[m[1]] {
				ok = true
			}
			for u := range units {
				if filepath.Base(u) == filepath.Base(m[1]) {
					ok = true
				}
			}
		}
		if !ok {
			t.Errorf("%s claims `proved:shipped` but names no file whose specs are checked by make proof", id)
		}
	}
	if checked < 5 {
		t.Errorf("only %d rows claim a proof on shipped code; either the programme shrank or the status marker changed", checked)
	}
	t.Logf("%d rows claim a proof on shipped code, each naming a file make proof verifies", checked)
}
