package remediation

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func prepareSandboxOwnership(root, home string, uid, gid uint32) error {
	if os.Geteuid() != 0 || uid == 0 || gid == 0 || uid > 1<<31-1 || gid > 1<<31-1 {
		return errors.New("native sandbox requires distinct non-root tool credentials")
	}
	temp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	for _, directory := range []string{root, home} {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(temp, absolute)
		if err != nil || !filepath.IsLocal(rel) || rel == "." || !strings.HasPrefix(strings.Split(rel, string(filepath.Separator))[0], "hibou-") {
			return errors.New("sandbox ownership is limited to private Hibou temporary workspaces")
		}
		for parent := filepath.Dir(absolute); parent != temp; parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() {
				return errors.New("unsafe sandbox workspace parent")
			}
			if err := os.Chmod(parent, 0o711); err != nil {
				return err
			}
		}
		scope, err := os.OpenRoot(absolute)
		if err != nil {
			return err
		}
		defer scope.Close()
		if err := filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Name() == ".git" {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return errors.New("sandbox workspace contains an unsupported file type")
			}
			relative, err := filepath.Rel(absolute, path)
			if err != nil {
				return err
			}
			if path == absolute {
				// Sticky, supervisor-owned directories protect .git while
				// allowing atomic dependency-file writes by the tool identity.
				if err := scope.Lchown(relative, 0, 0); err != nil {
					return err
				}
				return scope.Chmod(relative, os.ModeSticky|0o777)
			}
			if err := scope.Lchown(relative, int(uid), int(gid)); err != nil {
				return err
			}
			if info.IsDir() {
				return scope.Chmod(relative, 0o700)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
