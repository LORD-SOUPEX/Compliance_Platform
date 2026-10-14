package sessions

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const DefaultKeep = 5
const MaxKeep = 1000
const markerName = ".compliance-sessions-root"

var sessionName = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)

// Options controls a purge of a session runs directory.
type Options struct {
	Keep    int
	Reserve int
	Protect []string
}

// Result lists what the purge removed and why other entries were left.
type Result struct {
	Removed []string
	Kept    int
	Notes   []string
}

type candidate struct {
	name string
	when time.Time
}

// ValidateKeep rejects a retention count outside 1..1000.
func ValidateKeep(keep int) error {
	if keep < 1 || keep > MaxKeep {
		return fmt.Errorf("nombre de sessions hors bornes (1 à %d) : %d", MaxKeep, keep)
	}
	return nil
}

// Purge deletes the oldest recognized session directories until the ceiling holds.
// The root must be a real directory. Symlinks are never followed or removed.
func Purge(root string, opts Options) (Result, error) {
	var result Result
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			result.Removed = []string{}
			return result, nil
		}
		return result, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("racine des sessions refusée : %s est un lien symbolique", root)
	}
	if !info.IsDir() {
		return result, fmt.Errorf("racine des sessions refusée : %s n'est pas un dossier", root)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return result, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return result, err
	}
	protected := map[string]bool{}
	for _, name := range opts.Protect {
		protected[name] = true
	}
	var sessions []candidate
	for _, entry := range entries {
		name := entry.Name()
		path, ok, note := recognize(root, name)
		if note != "" {
			result.Notes = append(result.Notes, note)
		}
		if !ok {
			continue
		}
		marker, err := os.Lstat(filepath.Join(path, "session.json"))
		when := time.Time{}
		if err == nil {
			when = marker.ModTime()
		}
		sessions = append(sessions, candidate{name: name, when: when})
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].when.Equal(sessions[j].when) {
			return sessions[i].name < sessions[j].name
		}
		return sessions[i].when.Before(sessions[j].when)
	})
	if err := ValidateKeep(opts.Keep); err != nil && opts.Keep != 0 {
		return result, err
	}
	limit := opts.Keep
	if limit == 0 {
		limit = DefaultKeep
	}
	if opts.Reserve > 0 {
		if opts.Reserve > limit {
			opts.Reserve = limit
		}
		limit -= opts.Reserve
	}
	excess := len(sessions) - limit
	for _, item := range sessions {
		if excess <= 0 {
			break
		}
		if protected[item.name] {
			result.Notes = append(result.Notes, "conservée (protégée) : "+item.name)
			continue
		}
		if err := removeSession(root, item.name); err != nil {
			return result, err
		}
		result.Removed = append(result.Removed, item.name)
		excess--
	}
	if result.Removed == nil {
		result.Removed = []string{}
	}
	result.Kept = len(sessions) - len(result.Removed)
	return result, nil
}

// Summary is the single purge log line.
func Summary(result Result) string {
	return fmt.Sprintf("purge : %d sessions supprimées, %d conservées", len(result.Removed), result.Kept)
}

func recognize(root, name string) (string, bool, string) {
	if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", false, ""
	}
	path := filepath.Join(root, name)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false, "hors racine refusé : " + name
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", false, ""
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", false, "lien symbolique ignoré : " + name
	}
	if !info.IsDir() || !sessionName.MatchString(name) {
		return "", false, ""
	}
	marker := filepath.Join(path, "session.json")
	minfo, err := os.Lstat(marker)
	if err != nil || minfo.IsDir() || minfo.Mode()&os.ModeSymlink != 0 {
		return "", false, ""
	}
	return path, true, ""
}

// ResolveSessionRoot returns a dedicated session directory. A plain folder
// receives a compliance-sessions child. Disk roots, the home directory,
// system directories and the extension directory are refused.
func ResolveSessionRoot(chosen string, forbidden []string) (string, error) {
	if strings.TrimSpace(chosen) == "" {
		return "", fmt.Errorf("dossier des sessions vide")
	}
	abs, err := filepath.Abs(chosen)
	if err != nil {
		return "", err
	}
	if err := refuseDangerous(abs, forbidden); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("racine des sessions refusée : %s est un lien symbolique", abs)
	}
	if isDedicated(abs) {
		return abs, nil
	}
	return filepath.Join(abs, "compliance-sessions"), nil
}

func isDedicated(abs string) bool {
	if _, err := os.Lstat(filepath.Join(abs, markerName)); err == nil {
		return true
	}
	cleaned := filepath.Clean(abs)
	return strings.HasSuffix(strings.ToLower(filepath.ToSlash(cleaned)), "/.compliance/sessions/runs")
}

func refuseDangerous(abs string, forbidden []string) error {
	cleaned := filepath.Clean(abs)
	if volumeRoot(cleaned) {
		return fmt.Errorf("racine des sessions refusée : racine de disque %s", cleaned)
	}
	home, err := os.UserHomeDir()
	if err == nil && samePath(cleaned, home) {
		return fmt.Errorf("racine des sessions refusée : dossier personnel")
	}
	base := strings.ToLower(filepath.Base(cleaned))
	parentIsRoot := volumeRoot(filepath.Dir(cleaned))
	system := map[string]bool{"windows": true, "system32": true, "program files": true, "program files (x86)": true, "usr": true, "bin": true, "etc": true, "system": true}
	if parentIsRoot && system[base] {
		return fmt.Errorf("racine des sessions refusée : dossier système %s", cleaned)
	}
	for _, dir := range forbidden {
		if dir == "" {
			continue
		}
		forbiddenAbs, absErr := filepath.Abs(dir)
		if absErr != nil {
			continue
		}
		if samePath(cleaned, forbiddenAbs) || strings.HasPrefix(strings.ToLower(cleaned+string(filepath.Separator)), strings.ToLower(forbiddenAbs+string(filepath.Separator))) {
			return fmt.Errorf("racine des sessions refusée : dossier de l'extension")
		}
	}
	return nil
}

func volumeRoot(path string) bool {
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	rest = strings.Trim(rest, `\/`)
	return rest == ""
}

func samePath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func removeSession(root, name string) error {
	path, ok, note := recognize(root, name)
	if !ok {
		if note != "" {
			return fmt.Errorf("%s", note)
		}
		return fmt.Errorf("dossier non reconnu, suppression refusée : %s", name)
	}
	return os.RemoveAll(path)
}
