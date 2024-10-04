package gcs

import (
	"bytes"
	"encoding/binary"
	"github.com/koltiradw/gcs/coverage"
	"github.com/koltiradw/gcs/coverage/cformat"
	"github.com/koltiradw/gcs/coverage/cmerge"
	"github.com/koltiradw/gcs/coverage/decodecounter"
	"github.com/koltiradw/gcs/coverage/decodemeta"
	"github.com/koltiradw/gcs/coverage/slicereader"
	"github.com/koltiradw/gcs/coverage/slicewriter"
	"io"
	"log"
	"net"
	"os"
	cover "runtime/coverage"
)

const HOST = "0.0.0.0"
const TYPE = "tcp"
const PORT = "3001"

// WuppieFuzz proto for lcov coverage client
const HEADER_SIZE = 8

var REQUEST_HEADER = [...]byte{0x01, 0xC0, 0xC0, 0x10, 0x07}

const BLOCK_CMD_DUMP = 0x40

var COVERAGE_INFO_RESPONSE = []byte{0x11}
var CMD_OK_RESPONSE = []byte{0x20}

type pkfunc struct {
	pk, fcn uint32
}

type BatchCounterAlloc struct {
	pool []uint32
}

var meta_reader *decodemeta.CoverageMetaFileReader = nil

func (ca *BatchCounterAlloc) AllocateCounters(n int) []uint32 {
	const chunk = 8192
	if n > cap(ca.pool) {
		siz := chunk
		if n > chunk {
			siz = n
		}
		ca.pool = make([]uint32, siz)
	}
	rv := ca.pool[:n]
	ca.pool = ca.pool[n:]
	return rv
}

func getCounters() []byte {
	counters_writer := &slicewriter.WriteSeeker{}
	cover.WriteCounters(counters_writer)
	counters_writer.Seek(0, io.SeekStart)
	return counters_writer.BytesWritten()
}

func getMetaReader() (*decodemeta.CoverageMetaFileReader, error) {
	meta_writer := &slicewriter.WriteSeeker{}
	cover.WriteMeta(meta_writer)
	meta_writer.Seek(0, io.SeekStart)
	return decodemeta.NewCoverageMetaFileReader(meta_writer.BytesWritten())
}

func getLCOV() []byte {
	//gen profile file
	myformatter := cformat.NewFormatter(coverage.CtrModeAtomic)

	pmm := make(map[pkfunc][]uint32)

	counters_info := getCounters()

	counters_reader := slicereader.NewReader(counters_info, false)

	var cdr *decodecounter.CounterDataReader

	cdf := "covcounter"

	cm := cmerge.Merger{}
	bca := BatchCounterAlloc{}
	cdr, err := decodecounter.NewCounterDataReader(cdf, counters_reader)
	if err != nil {
		log.Fatalf("reading counter data file %s: %s", cdf, err)
	}
	var data decodecounter.FuncPayload
	for {
		ok, err := cdr.NextFunc(&data)
		if err != nil {
			log.Fatalf("reading counter data file %s: %v", cdf, err)
		}
		if !ok {
			break
		}

		// NB: sanity check on pkg and func IDs?
		key := pkfunc{pk: data.PkgIdx, fcn: data.FuncIdx}
		if prev, found := pmm[key]; found {
			// Note: no overflow reporting here.
			if err, _ := cm.MergeCounters(data.Counters, prev); err != nil {
				log.Fatalf("processing counter data file %s: %v", cdf, err)
			}
		}
		c := bca.AllocateCounters(len(data.Counters))
		copy(c, data.Counters)
		pmm[key] = c
	}

	if err != nil {
		log.Fatalf("failed with: %v", err)
	}

	if meta_reader == nil {
		meta_reader, _ = getMetaReader()
	}

	payload := []byte{}
	np := uint32(meta_reader.NumPackages())
	for pkIdx := uint32(0); pkIdx < np; pkIdx++ {
		var pd *decodemeta.CoverageMetaDataDecoder
		pd, payload, err = meta_reader.GetPackageDecoder(pkIdx, payload)
		if err != nil {
			log.Fatalf("reading pkg %d from meta-file: %s", pkIdx, err)
		}
		myformatter.SetPackage(pd.PackagePath())
		nf := pd.NumFuncs()
		var fd coverage.FuncDesc
		for fnIdx := uint32(0); fnIdx < nf; fnIdx++ {
			if err := pd.ReadFunc(fnIdx, &fd); err != nil {
				log.Fatalf("reading meta-data error : %v", err)
			}
			key := pkfunc{pk: pkIdx, fcn: fnIdx}
			counters, haveCounters := pmm[key]
			for i := 0; i < len(fd.Units); i++ {
				u := fd.Units[i]
				// Skip units with non-zero parent (no way to represent
				// these in the existing format).
				if u.Parent != 0 {
					continue
				}
				count := uint32(0)
				if haveCounters {
					count = counters[i]
				}
				myformatter.AddUnit(fd.Srcfile, fd.Funcname, fd.Lit, u, count)
			}
		}
	}

	lcov_buffer := new(bytes.Buffer)
	myformatter.EmitLcov(lcov_buffer)

	return lcov_buffer.Bytes()
}

func handleRequest(conn net.Conn) {
	buffer := make([]byte, 8)
	_, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	cmd := buffer[5]

	if int(cmd) == BLOCK_CMD_DUMP {
		lcov := getLCOV()
		size := make([]byte, 4)
		binary.LittleEndian.PutUint32(size, uint32(len(lcov)))
		conn.Write(COVERAGE_INFO_RESPONSE)
		conn.Write(size)
		conn.Write(lcov)
	}

	reset_byte := buffer[7]

	if int(reset_byte) != 0 {
		cover.ClearCounters()
	}

	conn.Write(CMD_OK_RESPONSE)
}

func init() {
	go startCoverageServer()
}

func startCoverageServer() {
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	defer listen.Close()

	conn, err := listen.Accept()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for {
		handleRequest(conn)
	}
}
