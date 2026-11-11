package xdpverdict

import (
	"context"
	"io"
	"os"
	"time"
)

// Tail follows complete lines from a newly created or rotated EVE file.
// Existing content on startup is skipped, avoiding replay of stale verdicts.
// A line larger than 1 MiB is discarded until its newline.
func Tail(ctx context.Context, path string, interval time.Duration, consume func([]byte)) error {
	const maxLine = 1 << 20
	var file *os.File
	var info os.FileInfo
	var offset int64
	var partial []byte
	var discard bool
	first := true
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		current, err := os.Stat(path)
		if err == nil {
			if file == nil || !os.SameFile(info, current) || current.Size() < offset {
				if file != nil {
					_ = file.Close()
				}
				file, err = os.Open(path)
				if err != nil {
					file = nil
				} else {
					info = current
					offset = 0
					partial = nil
					discard = false
					if first {
						offset, err = file.Seek(0, io.SeekEnd)
						if err != nil {
							return err
						}
					}
				}
			}
			if file != nil {
				first = false
				buf := make([]byte, 32768)
				for {
					n, e := file.Read(buf)
					offset += int64(n)
					for _, b := range buf[:n] {
						if b == '\n' {
							if !discard {
								consume(partial)
							}
							partial = nil
							discard = false
							continue
						}
						if !discard {
							if len(partial) >= maxLine {
								partial = nil
								discard = true
							} else {
								partial = append(partial, b)
							}
						}
					}
					if e != nil {
						if e != io.EOF {
							return e
						}
						break
					}
					if n == 0 {
						break
					}
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if first && file == nil {
			first = false
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
