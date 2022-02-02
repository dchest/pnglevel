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

	bufSize = 32768 // zlib reads in blocks of 32K
)

const (
	stStart = iota
	stChunkHead
	stChunkData
	stChunkCrc
	stIDAT
)

type Reader struct {
	r             io.Reader
	w             bytes.Buffer
	level         int
	tmp           [13]byte
	crc           hash.Hash32
	readNonIDAT   bool
	processedIDAT bool
	buf           []byte
	stage         int
	chunkLen      int
	chunkType     string
	zr            io.ReadCloser
	zw            *zlib.Writer
	zbuf          bytes.Buffer
	zcrc          hash.Hash32
	eof           bool
}

func Repack(w io.Writer, r io.Reader, level int) error {
	p := NewReader(r, level)
	_, err := io.Copy(w, p)
	if err != nil {
		return err
	}
	return nil
}

// Repack reads a PNG file from the given io.Reader and
// writes it recompressed with the given level to io.Writer.
func NewReader(r io.Reader, level int) io.Reader {
	return &Reader{
		r:     r,
		level: level,
		buf:   make([]byte, bufSize),
		crc:   crc32.NewIEEE(),
		zcrc:  crc32.NewIEEE(),
	}
}

func (p *Reader) Read(b []byte) (nn int, err error) {
	for p.w.Len() == 0 {
		if p.eof {
			return 0, io.EOF
		}
		if err := p.refill(); err != nil {
			if err == io.EOF {
				p.eof = true
				continue
			}
			return 0, err
		}
	}
	n, err := p.w.Read(b[:min(len(b), p.w.Len())])
	return n, err
}

func (p *Reader) refill() error {
	switch p.stage {
	case stStart:
		if err := p.verifyHeader(); err != nil {
			return err
		}
		p.stage = stChunkHead
	case stChunkHead:
		length, kind, err := p.chunkHeader()
		if err != nil {
			return err
		}
		if length > maxChunkLen {
			return errors.New("pnglevel: chunk is too big")
		}
		p.chunkLen = length
		p.chunkType = kind
		p.stage = stChunkData
	case stChunkData:
		if err := p.handleChunkData(); err != nil {
			return err
		}
	case stChunkCrc:
		if err := p.verifyCrc(); err != nil {
			return err
		}
		p.stage = stChunkHead
	case stIDAT:
		if err := p.handleIDAT(); err != nil {
			p.zr.Close()
			if err == io.EOF {
				if !p.readNonIDAT {
					// Verify checksum of last IDAT chunk without writing it.
					if _, err := io.ReadFull(p.r, p.tmp[:4]); err != nil {
						return err
					}
					if binary.BigEndian.Uint32(p.tmp[:4]) != p.crc.Sum32() {
						return fmt.Errorf("pnglevel: invalid checksum of IDAT chunk")
					}
					p.stage = stChunkHead
					return nil
				}
				p.stage = stChunkData
				return nil
			}
			return err
		}
	default:
		panic("pnglevel: programmer error, unknown stage")
	}
	return nil
}

func (p *Reader) handleChunkData() (err error) {
	if p.chunkType == "IDAT" {
		if p.processedIDAT {
			return errors.New("pnglevel: wrong IDAT order")
		}
		p.zr, err = zlib.NewReader(&idatReader{r: p})
		if err != nil {
			return err
		}
		p.zw, err = zlib.NewWriterLevel(&p.zbuf, p.level)
		if err != nil {
			return err
		}
		p.processedIDAT = true
		p.stage = stIDAT
		return nil
	}
	// Read and chunk write data.
	n, err := p.r.Read(p.buf[:min(len(p.buf), p.chunkLen)])
	if err != nil {
		return err
	}
	p.w.Write(p.buf[:n])
	p.crc.Write(p.buf[:n])
	p.chunkLen -= int(n)
	if p.chunkLen == 0 {
		p.stage = stChunkCrc
	}
	return nil
}

func (p *Reader) verifyHeader() error {
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
	length, kind, err := p.chunkHeader()
	if err != nil {
		return err
	}
	if kind != "IHDR" {
		return errors.New("pnglevel: missing IHDR")
	}
	if length != 13 {
		return errors.New("pnglevel: incorrect IHDR length")
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
	return nil
}

func (p *Reader) chunkHeader() (length int, kind string, err error) {
	if _, err := io.ReadFull(p.r, p.tmp[:8]); err != nil {
		return 0, "", err
	}
	ulen := binary.BigEndian.Uint32(p.tmp[:4])
	if ulen > maxChunkLen {
		return 0, "", errors.New("pnglevel: chunk is too big")
	}
	length = int(ulen)
	kind = string(p.tmp[4:8])
	if kind != "IDAT" {
		// Write chunk header.
		p.w.Write(p.tmp[:8])
	}
	p.crc.Reset()
	p.crc.Write(p.tmp[4:8])
	return
}

func (p *Reader) verifyCrc() error {
	if _, err := io.ReadFull(p.r, p.tmp[:4]); err != nil {
		return err
	}
	if binary.BigEndian.Uint32(p.tmp[:4]) != p.crc.Sum32() {
		return errors.New("pnglevel: invalid checksum")
	}
	p.w.Write(p.tmp[:4])
	p.crc.Reset()
	return nil
}

func (p *Reader) handleIDAT() error {
	nr, rerr := p.zr.Read(p.buf)
	if rerr != nil && rerr != io.EOF {
		return rerr
	}
	_, err := p.zw.Write(p.buf[:nr])
	if err != nil {
		return err
	}
	err = p.zw.Flush()
	if err != nil {
		return err
	}
	if rerr == io.EOF {
		p.zw.Close()
	}
	// Write length, chunk name, chunk data, crc.
	err = binary.Write(&p.w, binary.BigEndian, uint32(p.zbuf.Len()))
	if err != nil {
		return err
	}
	_, err = io.WriteString(&p.w, "IDAT")
	if err != nil {
		return err
	}
	_, err = p.w.Write(p.zbuf.Bytes())
	if err != nil {
		return err
	}
	io.WriteString(p.zcrc, "IDAT")
	p.zcrc.Write(p.zbuf.Bytes())
	err = binary.Write(&p.w, binary.BigEndian, p.zcrc.Sum32())
	if err != nil {
		return err
	}
	p.zcrc.Reset()
	p.zbuf.Reset()
	if rerr == io.EOF {
		return io.EOF
	}
	return nil
}

type idatReader struct {
	r *Reader
}

func (p *idatReader) Read(b []byte) (nn int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	for p.r.chunkLen == 0 {
		if _, err := io.ReadFull(p.r.r, p.r.tmp[:4]); err != nil {
			return 0, err
		}
		if binary.BigEndian.Uint32(p.r.tmp[:4]) != p.r.crc.Sum32() {
			return nn, fmt.Errorf("pnglevel: invalid checksum of IDAT chunk")
		}
		if _, err := io.ReadFull(p.r.r, p.r.tmp[:8]); err != nil {
			return 0, err
		}
		ulen := binary.BigEndian.Uint32(p.r.tmp[:4])
		if ulen > maxChunkLen {
			return 0, errors.New("pnglevel: chunk is too big")
		}
		p.r.chunkLen = int(ulen)
		if p.r.chunkLen > maxChunkLen {
			return 0, errors.New("pnglevel: IDAT chunk is too big")
		}
		p.r.chunkType = string(p.r.tmp[4:8])
		p.r.crc.Reset()
		p.r.crc.Write(p.r.tmp[4:8])
		if p.r.chunkType != "IDAT" {
			p.r.readNonIDAT = true
			return 0, io.EOF
		}
	}
	n, err := p.r.r.Read(b[:min(len(b), p.r.chunkLen)])
	p.r.crc.Write(b[:n])
	p.r.chunkLen -= n
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
