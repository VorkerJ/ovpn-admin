package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Errorln(err)
	}
	return t
}

func parseDateToString(layout, datetime, format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

// fExist returns true only when path exists and is statable. Any other error
// (permission denied, IO failure, …) is logged at warn level and treated as
// "doesn't exist" — previously this called log.Fatalf and crashed the daemon
// on a transient stat failure.
func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Warnf("fExist(%s): %v", path, err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning(err)
		return ""
	}

	return string(content)
}

func fWrite(path, content string) error {
	if err := ioutil.WriteFile(path, []byte(content), 0600); err != nil {
		log.Errorf("fWrite(%s): %v", path, err)
		return err
	}
	return nil
}

func fDelete(path string) error {
	if err := os.Remove(path); err != nil {
		log.Errorf("fDelete(%s): %v", path, err)
		return err
	}
	return nil
}

func fCopy(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories, symlinks, devices, etc.)
		return fmt.Errorf("fCopy: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("fCopy: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return err
		}
	}
	if err = os.Link(src, dst); err == nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}

func fMove(src, dst string) error {
	err := fCopy(src, dst)
	if err != nil {
		log.Warn(err)
		return err
	}
	err = fDelete(src)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}

