package util

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func ParseSSHTimespec(value string) (time.Time, error) {
	switch len(value) {
	case 8: // YYYYMMDD (using local timezone)
		return time.ParseInLocation("20060102", value, time.Local)
	case 9: // YYYYMMDDZ (using UTC)
		return time.Parse("20060102Z", value)
	case 12: // YYYYMMDDHHMM (using local timezone)
		return time.ParseInLocation("200601021504", value, time.Local)
	case 13: // YYYYMMDDHHMMZ (using UTC)
		return time.Parse("200601021504Z", value)
	case 15: // YYYYMMDDHHMMSS (using local timezone)
		return time.ParseInLocation("20060102150405", value, time.Local)
	case 16: // YYYYMMDDHHMMSSZ (using UTC)
		return time.Parse("20060102150405Z", value)
	default:
		return time.Time{}, fmt.Errorf("invalid timespec: %s", value)
	}
}

func ShowNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		err := exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	case "linux":
		err := exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	}
}

func ParseTimePattern(patt string) (time.Time, time.Time, error) {
	// TODO support more patterns
	// non-relative (like iso8601)
	// weeks, months, years, etc
	if strings.Contains(patt, ":") {
		parts := strings.Split(patt, ":")
		if len(parts) != 2 {
			return time.Time{}, time.Time{}, errors.New("invalid time pattern, must contain 0 or 1 ':'")
		}
		duration1, err := time.ParseDuration(parts[0])
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		duration2, err := time.ParseDuration(parts[1])
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		return time.Now().Add(duration1), time.Now().Add(duration2), nil
	} else {
		duration, err := time.ParseDuration(patt)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		if duration < 0 {
			return time.Now().Add(duration), time.Now(), nil
		} else {
			return time.Now(), time.Now().Add(duration), nil

		}
	}
}

func RenderTime(seconds uint64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 60*60 {
		return fmt.Sprintf("%.1fm", float64(seconds)/60)
	} else if seconds < 24*60*60 {
		return fmt.Sprintf("%.1fh", float64(seconds)/60/60)
	} else {
		return fmt.Sprintf("%.1fd", float64(seconds)/60/60/24)
	}
}
