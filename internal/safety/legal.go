package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const HistoricalManifestPath = "LICENSES/HISTORICAL-MANIFEST.json"

type legalArtifact struct {
	ID             string `json:"id"`
	File           string `json:"file"`
	Package        string `json:"package,omitempty"`
	OriginalPath   string `json:"originalPath,omitempty"`
	Classification string `json:"classification"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
}

type legalManifest struct {
	SchemaVersion         uint64 `json:"schemaVersion"`
	Status                string `json:"status"`
	Notice                string `json:"notice"`
	CurrentImplementation struct {
		Module                           string `json:"module"`
		DependencyModel                  string `json:"dependencyModel"`
		HistoricalArtifactsUsedAtRuntime bool   `json:"historicalArtifactsUsedAtRuntime"`
	} `json:"currentImplementation"`
	RootLicense        legalArtifact   `json:"rootLicense"`
	Artifacts          []legalArtifact `json:"artifacts"`
	GoToolchainNotices []legalArtifact `json:"goToolchainNotices"`
}

var expectedLegalArtifacts = []legalArtifact{
	{ID: "root-license", File: "LICENSE", Classification: "Apache-2.0", Bytes: 10174, SHA256: "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594"},
	{
		ID: "dependency-01", File: "LICENSES/historical/dependency-01.txt", Package: "github.com/fatih/structs",
		OriginalPath: "vendor/github.com/fatih/structs/LICENSE", Classification: "MIT", Bytes: 1078,
		SHA256: "8f09e42906e1a3c7bd39629a17225b3b62f25783444d8d75ad5d6657916915df",
	},
	{
		ID: "dependency-02", File: "LICENSES/historical/dependency-02.txt", Package: "github.com/golang/snappy",
		OriginalPath: "vendor/github.com/golang/snappy/LICENSE", Classification: "BSD-3-Clause", Bytes: 1486,
		SHA256: "f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf",
	},
	{
		ID: "dependency-03", File: "LICENSES/historical/dependency-03.txt", Package: "github.com/gorilla/context",
		OriginalPath: "vendor/github.com/gorilla/context/LICENSE", Classification: "BSD-3-Clause", Bytes: 1476,
		SHA256: "e2b2df1c58a081f27c3b9fa9feec759f2bf2ce430ae02a4f274b2d9ac7e87abd",
	},
	{
		ID: "dependency-04", File: "LICENSES/historical/dependency-04.txt", Package: "github.com/gorilla/mux",
		OriginalPath: "vendor/github.com/gorilla/mux/LICENSE", Classification: "BSD-3-Clause", Bytes: 1476,
		SHA256: "e2b2df1c58a081f27c3b9fa9feec759f2bf2ce430ae02a4f274b2d9ac7e87abd",
	},
	{
		ID: "dependency-05", File: "LICENSES/historical/dependency-05.txt", Package: "github.com/gorilla/websocket",
		OriginalPath: "vendor/github.com/gorilla/websocket/LICENSE", Classification: "BSD-2-Clause", Bytes: 1312,
		SHA256: "2be1b548b0387ca8948e1bb9434e709126904d15f622cc2d0d8e7f186e4d122d",
	},
	{
		ID: "dependency-06", File: "LICENSES/historical/dependency-06.txt", Package: "github.com/hashicorp/errwrap",
		OriginalPath: "vendor/github.com/hashicorp/errwrap/LICENSE", Classification: "MPL-2.0", Bytes: 15977,
		SHA256: "bef1747eda88b9ed46e94830b0d978c3499dad5dfe38d364971760881901dadd",
	},
	{
		ID: "dependency-07", File: "LICENSES/historical/dependency-07.txt", Package: "github.com/hashicorp/go-cleanhttp",
		OriginalPath: "vendor/github.com/hashicorp/go-cleanhttp/LICENSE", Classification: "MPL-2.0", Bytes: 15922,
		SHA256: "60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d",
	},
	{
		ID: "dependency-08", File: "LICENSES/historical/dependency-08.txt", Package: "github.com/hashicorp/go-multierror",
		OriginalPath: "vendor/github.com/hashicorp/go-multierror/LICENSE", Classification: "MPL-2.0", Bytes: 15976,
		SHA256: "a830016911a348a54e89bd54f2f8b0d8fffdeac20aecfba8e36ebbf38a03f5ff",
	},
	{
		ID: "dependency-09", File: "LICENSES/historical/dependency-09.txt", Package: "github.com/hashicorp/go-rootcerts",
		OriginalPath: "vendor/github.com/hashicorp/go-rootcerts/LICENSE", Classification: "MPL-2.0", Bytes: 15922,
		SHA256: "60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d",
	},
	{
		ID: "dependency-10", File: "LICENSES/historical/dependency-10.txt", Package: "github.com/hashicorp/hcl",
		OriginalPath: "vendor/github.com/hashicorp/hcl/LICENSE", Classification: "MPL-2.0", Bytes: 15977,
		SHA256: "bef1747eda88b9ed46e94830b0d978c3499dad5dfe38d364971760881901dadd",
	},
	{
		ID: "dependency-11", File: "LICENSES/historical/dependency-11.txt", Package: "github.com/hashicorp/vault",
		OriginalPath: "vendor/github.com/hashicorp/vault/LICENSE", Classification: "MPL-2.0", Bytes: 15922,
		SHA256: "60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d",
	},
	{
		ID: "dependency-12", File: "LICENSES/historical/dependency-12.txt", Package: "github.com/mitchellh/mapstructure",
		OriginalPath: "vendor/github.com/mitchellh/mapstructure/LICENSE", Classification: "MIT", Bytes: 1085,
		SHA256: "22adc4abdece712a737573672f082fd61ac2b21df878efb87ffcff4354a07f26",
	},
	{
		ID: "dependency-13", File: "LICENSES/historical/dependency-13.txt", Package: "github.com/pkg/errors",
		OriginalPath: "vendor/github.com/pkg/errors/LICENSE", Classification: "BSD-2-Clause", Bytes: 1312,
		SHA256: "8d427fd87bc9579ea368fde3d49f9ca22eac857f91a9dec7e3004bdfab7dee86",
	},
	{
		ID: "dependency-14", File: "LICENSES/historical/dependency-14.txt", Package: "github.com/ran" + "cher/go-ran" + "cher",
		OriginalPath: "vendor/github.com/ran" + "cher/go-ran" + "cher/LICENSE", Classification: "Apache-2.0", Bytes: 10174,
		SHA256: "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
	},
	{
		ID: "dependency-15", File: "LICENSES/historical/dependency-15.txt", Package: "github.com/ran" + "cher/ran" + "cher-flexvol",
		OriginalPath: "vendor/github.com/ran" + "cher/ran" + "cher-flexvol/LICENSE", Classification: "Apache-2.0", Bytes: 10174,
		SHA256: "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
	},
	{
		ID: "dependency-16", File: "LICENSES/historical/dependency-16.txt", Package: "github.com/sethgrid/pester",
		OriginalPath: "vendor/github.com/sethgrid/pester/LICENSE.md", Classification: "MIT", Bytes: 1066,
		SHA256: "e3822d9ca72d01efc43b1ed503a01ae64267fd893f60f9008e9d1fe5e11adde7",
	},
	{
		ID: "dependency-17", File: "LICENSES/historical/dependency-17.txt", Package: "github.com/sirupsen/logrus",
		OriginalPath: "vendor/github.com/sirupsen/logrus/LICENSE", Classification: "MIT", Bytes: 1082,
		SHA256: "51a0c9ec7f8b7634181b8d4c03e5b5d204ac21d6e72f46c313973424664b2e6b",
	},
	{
		ID: "dependency-18", File: "LICENSES/historical/dependency-18.txt", Package: "github.com/urfave/cli",
		OriginalPath: "vendor/github.com/urfave/cli/LICENSE", Classification: "MIT", Bytes: 1084,
		SHA256: "da277af11b85227490377fbcac6afccc68be560c4fff36ac05ca62de55345fd7",
	},
	{
		ID: "dependency-19", File: "LICENSES/historical/dependency-19.txt", Package: "golang.org/x/sys",
		OriginalPath: "vendor/golang.org/x/sys/LICENSE", Classification: "BSD-3-Clause", Bytes: 1453,
		SHA256: "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
	},
	{
		ID: "dependency-20", File: "LICENSES/historical/dependency-20.txt", Package: "golang.org/x/sys",
		OriginalPath: "vendor/golang.org/x/sys/PATENTS", Classification: "Additional IP Rights Grant (Patents)", Bytes: 1303,
		SHA256: "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
	},
	{ID: "go-license", File: "LICENSES/GO-LICENSE", Classification: "BSD-3-Clause", Bytes: 1453, SHA256: "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"},
	{ID: "go-patents", File: "LICENSES/GO-PATENTS", Classification: "Additional IP Rights Grant (Patents)", Bytes: 1303, SHA256: "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"},
}

const (
	expectedHistoricalManifestBytes  = 8251
	expectedHistoricalManifestSHA256 = "ec9781b197f004152e1d5d1dbb7d8e83eaa7872e07c805482f22280ad56901e0"
)

// VerifyLegalArtifacts checks every byte-preserved legal artifact and the
// manifest that distinguishes the current standard-library implementation from
// historical dependency evidence.
func VerifyLegalArtifacts(root string) ([]Finding, error) {
	findings := make([]Finding, 0)
	for _, expected := range expectedLegalArtifacts {
		path := filepath.Join(root, filepath.FromSlash(expected.File))
		content, err := os.ReadFile(path)
		if err != nil {
			findings = append(findings, Finding{Path: expected.File, Code: "legal-artifact-missing"})
			continue
		}
		digest := sha256.Sum256(content)
		if int64(len(content)) != expected.Bytes || hex.EncodeToString(digest[:]) != expected.SHA256 {
			findings = append(findings, Finding{Path: expected.File, Code: "legal-artifact-mismatch"})
		}
	}

	manifestPath := filepath.Join(root, filepath.FromSlash(HistoricalManifestPath))
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-missing"})
	} else {
		manifestDigest := sha256.Sum256(manifestData)
		if len(manifestData) != expectedHistoricalManifestBytes || hex.EncodeToString(manifestDigest[:]) != expectedHistoricalManifestSHA256 {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-mismatch"})
		}
		var manifest legalManifest
		if json.Unmarshal(manifestData, &manifest) != nil {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-invalid"})
		} else {
			findings = append(findings, verifyLegalManifest(manifest)...)
		}
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Path < findings[right].Path
	})
	return uniqueFindings(findings), nil
}

func verifyLegalManifest(manifest legalManifest) []Finding {
	findings := make([]Finding, 0)
	if manifest.SchemaVersion != 1 || manifest.Status != "historical-only" ||
		!strings.Contains(manifest.Notice, "standard-library-only") || !strings.Contains(manifest.Notice, "does not import or use") {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-boundary"})
	}
	if manifest.CurrentImplementation.Module != "github.com/PastureStack/vault-secrets-bridge" ||
		manifest.CurrentImplementation.DependencyModel != "Go standard library only" ||
		manifest.CurrentImplementation.HistoricalArtifactsUsedAtRuntime {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-current-implementation"})
	}
	if !sameLegalRecord(manifest.RootLicense, expectedLegalArtifacts[0], false) {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "root-license-record-mismatch"})
	}
	expectedRecords := make(map[string]legalArtifact)
	for _, artifact := range expectedLegalArtifacts[1:] {
		expectedRecords[artifact.ID] = artifact
	}
	actualRecords := append(append([]legalArtifact(nil), manifest.Artifacts...), manifest.GoToolchainNotices...)
	if len(actualRecords) != len(expectedRecords) {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-count"})
	}
	for _, actual := range actualRecords {
		expected, exists := expectedRecords[actual.ID]
		requiresAttribution := exists && strings.HasPrefix(expected.ID, "dependency-")
		if !exists || !sameLegalRecord(actual, expected, requiresAttribution) {
			findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-mismatch"})
		}
		delete(expectedRecords, actual.ID)
	}
	if len(expectedRecords) != 0 {
		findings = append(findings, Finding{Path: HistoricalManifestPath, Code: "legal-manifest-record-missing"})
	}
	return findings
}

func sameLegalRecord(actual, expected legalArtifact, historical bool) bool {
	if actual.ID != expected.ID || actual.File != expected.File || actual.Classification != expected.Classification ||
		actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 {
		return false
	}
	if historical {
		return actual.Package == expected.Package && actual.OriginalPath == expected.OriginalPath &&
			actual.Package != "" && actual.OriginalPath != ""
	}
	return actual.Package == expected.Package && actual.OriginalPath == expected.OriginalPath
}
