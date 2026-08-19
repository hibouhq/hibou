package callgraph

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ScanJavaClassReferences walks a compiled-classes tree (e.g. target/classes,
// build/classes, or a jar/war) and returns every Java package the bytecode
// references, parsed from the constant pools of the application's own .class
// files. This is CLASS-level reachability input: "the app's bytecode mentions
// org.apache.logging.log4j" — coarser than a call graph, but computed from
// what the compiler actually linked, not from manifests.
func ScanJavaClassReferences(root string) ([]string, error) {
	packages := map[string]struct{}{}
	classCount := 0

	scan := func(name string, reader io.Reader) {
		classes, err := classConstantPoolClasses(reader)
		if err != nil {
			return // one unreadable class must not sink the scan
		}
		classCount++
		for _, class := range classes {
			if pkg := packageOfClass(class); pkg != "" {
				packages[pkg] = struct{}{}
			}
		}
	}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// A repo-root scan is the multi-module answer, but test output and
			// unpacked dependencies are not the app's own references — skip
			// them so the inventory reflects production code.
			switch entry.Name() {
			case "test-classes", "node_modules", ".git", "dependency":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".class"):
			file, err := os.Open(path) // #nosec G122 G304 -- CI-side scan of the caller's own checkout; no trust boundary.
			if err != nil {
				return nil
			}
			scan(path, file)
			file.Close()
		case strings.HasSuffix(path, ".jar") || strings.HasSuffix(path, ".war"):
			archive, err := zip.OpenReader(path)
			if err != nil {
				return nil
			}
			for _, entry := range archive.File {
				if !strings.HasSuffix(entry.Name, ".class") {
					continue
				}
				reader, err := entry.Open()
				if err != nil {
					continue
				}
				scan(entry.Name, reader)
				reader.Close()
			}
			archive.Close()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if classCount == 0 {
		return nil, fmt.Errorf("no .class files under %s — compile first (e.g. mvn compile) and point at the classes directory", root)
	}

	out := make([]string, 0, len(packages))
	for pkg := range packages {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out, nil
}

// classConstantPoolClasses parses one .class file's constant pool and returns
// the class names it references (JVM spec §4.4). Only Utf8 and Class entries
// are decoded; everything else is skipped by its fixed size.
func classConstantPoolClasses(r io.Reader) ([]string, error) {
	read := func(buffer []byte) error {
		_, err := io.ReadFull(r, buffer)
		return err
	}
	header := make([]byte, 10) // magic u4, minor u2, major u2, cp count u2
	if err := read(header); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(header) != 0xCAFEBABE {
		return nil, errors.New("not a class file")
	}
	poolCount := int(binary.BigEndian.Uint16(header[8:]))

	utf8ByIndex := map[int]string{}
	classNameIndexes := []int{}
	scratch := make([]byte, 8)

	for index := 1; index < poolCount; index++ {
		if err := read(scratch[:1]); err != nil {
			return nil, err
		}
		switch tag := scratch[0]; tag {
		case 1: // Utf8: u2 length + bytes
			if err := read(scratch[:2]); err != nil {
				return nil, err
			}
			length := int(binary.BigEndian.Uint16(scratch))
			value := make([]byte, length)
			if err := read(value); err != nil {
				return nil, err
			}
			utf8ByIndex[index] = string(value)
		case 7: // Class: u2 name index
			if err := read(scratch[:2]); err != nil {
				return nil, err
			}
			classNameIndexes = append(classNameIndexes, int(binary.BigEndian.Uint16(scratch)))
		case 8, 16, 19, 20: // String, MethodType, Module, Package: u2
			if err := read(scratch[:2]); err != nil {
				return nil, err
			}
		case 15: // MethodHandle: u1 + u2
			if err := read(scratch[:3]); err != nil {
				return nil, err
			}
		case 3, 4, 9, 10, 11, 12, 17, 18: // 4-byte entries
			if err := read(scratch[:4]); err != nil {
				return nil, err
			}
		case 5, 6: // Long/Double: 8 bytes AND occupy two pool slots
			if err := read(scratch[:8]); err != nil {
				return nil, err
			}
			index++
		default:
			return nil, fmt.Errorf("unknown constant pool tag %d", tag)
		}
	}

	classes := make([]string, 0, len(classNameIndexes))
	for _, nameIndex := range classNameIndexes {
		if name, ok := utf8ByIndex[nameIndex]; ok {
			classes = append(classes, name)
		}
	}
	return classes, nil
}

// packageOfClass converts a JVM internal class name (org/apache/Foo, or an
// array descriptor like [Lorg/apache/Foo;) to its dotted package.
func packageOfClass(internal string) string {
	internal = strings.TrimLeft(internal, "[")
	internal = strings.TrimPrefix(internal, "L")
	internal = strings.TrimSuffix(internal, ";")
	slash := strings.LastIndex(internal, "/")
	if slash <= 0 {
		return ""
	}
	return strings.ReplaceAll(internal[:slash], "/", ".")
}
