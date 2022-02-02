// Package pnglevel changes zlib compression level of PNG files.
package pnglevel

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

const (
	pngHeader   = "\x89PNG\r\n\x1a\n"
	maxChunkLen = 0x7fffffff

	// We want to write approximate 64K IDAT chunks when level is 0.
	bufSize = (1 << 16) - 10 /* zlib header + adler checksum */
)

type repacker struct {
	r             io.Reader
	w             io.Writer
	level         int
	tmp           [13]byte
	crc           hash.Hash32
	idatLength    uint32
	haveLastChunk bool
	haveIDAT      bool
	buf           []byte
}

// Repack reads a PNG file from the given io.Reader and
// writes it recompressed with the given level to io.Writer.
func Repack(w io.Writer, r io.Reader, level int) error {
	p := &repacker{
		r:     r,
		w:     w,
		level: level,
		crc:   crc32.NewIEEE(),
		buf:   make([]byte, bufSize),
	}
	return p.repack()
}

func (p *repacker) repack() error {
	if err := p.header(); err != nil {
		return err
	}

	for {
		length, kind, err := p.chunk()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if kind == "IDAT" {
			if p.haveIDAT {
				return errors.New("pnglevel: wrong IDAT order")
			}
			if err := p.handleIDAT(length); err != nil {
				return err
			}
			p.haveIDAT = true
			// Chunk after IDAT
			if !p.haveLastChunk {
				// Verify checksum.
				if _, err := io.ReadFull(p.r, p.tmp[:4]); err != nil {
					return err
				}
				if binary.BigEndian.Uint32(p.tmp[:4]) != p.crc.Sum32() {
					return fmt.Errorf("pnglevel: invalid checksum of IDAT chunk")
				}
				continue
			}
			ulen := binary.BigEndian.Uint32(p.tmp[:4])
			if ulen > maxChunkLen {
				return errors.New("pnglevel: chunk is too big")
			}
			length = int(ulen)
		}
		if err := p.handleAnyChunk(length); err != nil {
			return err
		}
	}
}

func (p *repacker) header() error {
	// Verify PNG file signature.
	if _, err := io.ReadFull(p.r, p.tmp[:8]); err != nil {
		return err
	}
	if string(p.tmp[:8]) != pngHeader {
		return errors.New("pnglevel: not a PNG file")
	}
	if _, err := p.w.Write(p.tmp[:8]); err != nil {
		return err
	}

	// Read IHDR chunk.
	length, kind, err := p.chunk()
	if err != nil {
		return err
	}
	if kind != "IHDR" {
		return errors.New("pnglevel: missing IHDR")
	}
	if length != 13 {
		return errors.New("pnglevel: incorrect IHDR length")
	}
	if _, err := p.w.Write(p.tmp[:8]); err != nil {
		return err
	}
	if _, err := io.ReadFull(p.r, p.tmp[:13]); err != nil {
		return err
	}
	if p.tmp[10] != 0 {
		return errors.New("pnglevel: unsupported compression method")
	}
	p.crc.Write(p.tmp[:13])
	if _, err := p.w.Write(p.tmp[:13]); err != nil {
		return err
	}
	if err := p.verifyCrc(); err != nil {
		return err
	}
	_, err = p.w.Write(p.tmp[:4])
	if err != nil {
		return err
	}
	return nil
}

func (p *repacker) chunk() (length int, kind string, err error) {
	if _, err := io.ReadFull(p.r, p.tmp[:8]); err != nil {
		return 0, "", err
	}
	ulen := binary.BigEndian.Uint32(p.tmp[:4])
	if ulen > maxChunkLen {
		return 0, "", errors.New("pnglevel: chunk is too big")
	}
	length = int(ulen)
	kind = string(p.tmp[4:8])
	p.crc.Reset()
	p.crc.Write(p.tmp[4:8])
	return
}

func (p *repacker) handleAnyChunk(length int) error {
	// Write what we read in chunk().
	_, err := p.w.Write(p.tmp[:8])
	if err != nil {
		return err
	}
	// Copy the chunk.
	_, err = io.CopyN(io.MultiWriter(p.w, p.crc), p.r, int64(length))
	if err != nil {
		return err
	}
	// Verify crc.
	err = p.verifyCrc()
	if err != nil {
		return err
	}
	// Copy the crc.
	_, err = p.w.Write(p.tmp[:4])
	if err != nil {
		return err
	}
	return nil
}

func (p *repacker) verifyCrc() error {
	if _, err := io.ReadFull(p.r, p.tmp[:4]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(p.tmp[:4]) != p.crc.Sum32() {
		return errors.New("pnglevel: invalid checksum")
	}
	return nil
}

func (p *repacker) handleIDAT(length int) error {
	p.idatLength = uint32(length)
	var buf bytes.Buffer
	zr, err := zlib.NewReader(p)
	if err != nil {
		return err
	}
	defer zr.Close()
	icrc := crc32.NewIEEE()
	zw, err := zlib.NewWriterLevel(&buf, p.level)
	if err != nil {
		return err
	}
	defer zw.Close()
	eof := false
	for !eof {
		nr, err := zr.Read(p.buf)
		if err != nil {
			if err != io.EOF {
				return err
			}
			eof = true
		}
		if nr == 0 {
			continue
		}
		_, err = zw.Write(p.buf[:nr])
		if err != nil {
			return err
		}
		err = zw.Flush()
		if err != nil {
			return err
		}
		// Write length, chunk name, chunk data, crc.
		err = binary.Write(p.w, binary.BigEndian, uint32(buf.Len()))
		if err != nil {
			return err
		}
		_, err = io.WriteString(p.w, "IDAT")
		if err != nil {
			return err
		}
		_, err = p.w.Write(buf.Bytes())
		if err != nil {
			return err
		}
		icrc.Write([]byte("IDAT"))
		icrc.Write(buf.Bytes())
		err = binary.Write(p.w, binary.BigEndian, icrc.Sum32())
		if err != nil {
			return err
		}
		icrc.Reset()
		buf.Reset()
	}
	return nil
}

func (p *repacker) Read(b []byte) (nn int, err error) {
	// Copied mostly from image/png
	if len(b) == 0 {
		return 0, nil
	}
	for p.idatLength == 0 {
		if _, err := io.ReadFull(p.r, p.tmp[:4]); err != nil {
			return 0, err
		}
		if binary.BigEndian.Uint32(p.tmp[:4]) != p.crc.Sum32() {
			return nn, fmt.Errorf("pnglevel: invalid checksum of IDAT chunk")
		}
		if _, err := io.ReadFull(p.r, p.tmp[:8]); err != nil {
			return 0, err
		}
		p.idatLength = binary.BigEndian.Uint32(p.tmp[:4])
		if string(p.tmp[4:8]) != "IDAT" {
			p.haveLastChunk = true
			return 0, io.EOF
		}
		p.crc.Reset()
		p.crc.Write(p.tmp[4:8])
	}
	if p.idatLength > maxChunkLen {
		return 0, errors.New("pnglevel: IDAT chunk is too big")
	}
	n, err := p.r.Read(b[:min(len(b), int(p.idatLength))])
	p.crc.Write(b[:n])
	p.idatLength -= uint32(n)
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
