package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// manifest is a bundle's manifest.json (docs/18 A5).
type manifest struct {
	BundleID        string    `json:"bundle_id"`
	ProducedAt      time.Time `json:"produced_at"`
	ProducerBuild   string    `json:"producer_build"`
	VerifierVersion string    `json:"verifier_version"`
	Items           []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"items"`
}

// verifyManifest checks every listed member's sha256 and that no member is unlisted. From then on
// only members whose hash matched are read (source.listed).
func verifyManifest(r *Report, src *source) {
	raw, ok, err := src.read(MemberManifest)
	switch {
	case err != nil:
		r.add(SectionManifest, MemberManifest, Fail, "reading it: %v", err)
		return
	case !ok:
		r.add(SectionManifest, MemberManifest, NotChecked, "%s %s: the members' sha256 are not checked", MemberManifest, NotPresent)
		return
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		r.add(SectionManifest, MemberManifest, Fail, "not a bundle manifest: %v", err)
		src.listed = map[string]string{}
		return
	}
	r.add(SectionManifest, "bundle", Info, "bundle %s produced %s by build %s; it names verifier %s, this is %s",
		orNA(m.BundleID), m.ProducedAt.UTC().Format(time.RFC3339), orNA(m.ProducerBuild), orNA(m.VerifierVersion), Version)
	listed := map[string]string{}
	var problems []string
	matched := 0
	for _, it := range m.Items {
		p := path.Clean(it.Path)
		switch {
		case !fs.ValidPath(p) || p == "." || p != it.Path:
			problems = append(problems, "unsafe or non-canonical path "+oneLine(it.Path))
			continue
		case p == MemberManifest:
			problems = append(problems, "the manifest lists itself")
			continue
		}
		if _, dup := listed[p]; dup {
			problems = append(problems, "listed twice: "+p)
			continue
		}
		data, ok, err := src.read(p)
		switch {
		case err != nil:
			problems = append(problems, p+": "+err.Error())
			continue
		case !ok:
			problems = append(problems, "missing: "+p)
			continue
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), it.SHA256) {
			problems = append(problems, "sha256 differs: "+p)
			continue
		}
		listed[p] = it.SHA256
		matched++
	}
	all, err := allFiles(src.fsys)
	if err != nil {
		problems = append(problems, "listing the bundle: "+err.Error())
	}
	for _, f := range all {
		if f == MemberManifest {
			continue
		}
		if _, ok := listed[f]; !ok && !listedPath(m, f) {
			problems = append(problems, "not in the manifest (not read): "+oneLine(f))
		}
	}
	src.listed = listed
	if len(problems) > 0 {
		sort.Strings(problems)
		r.add(SectionManifest, "members", Fail, "%d of %d listed member(s) match; %s", matched, len(m.Items), strings.Join(problems, "; "))
		return
	}
	r.add(SectionManifest, "members", Pass, "%d listed member(s), every sha256 matches, none unlisted", matched)
}

func listedPath(m manifest, p string) bool {
	for _, it := range m.Items {
		if it.Path == p {
			return true
		}
	}
	return false
}

func allFiles(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, p)
		} else if !d.IsDir() {
			return errors.New("a member is neither a file nor a directory: " + oneLine(p))
		}
		if len(out) > maxMembers {
			return errors.New("too many members")
		}
		return nil
	})
	return out, err
}
