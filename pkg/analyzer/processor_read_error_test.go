package analyzer

import (
	"errors"
	"testing"

	"github.com/DanielDietz-de/TraceSleuth/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type permanentlyBrokenCaptureReader struct {
	calls int
}

func (r *permanentlyBrokenCaptureReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	r.calls++
	return nil, gopacket.CaptureInfo{}, errors.New("unrecoverable packet framing error")
}

func (r *permanentlyBrokenCaptureReader) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func TestProcessStopsAfterPersistentReaderErrors(t *testing.T) {
	reader := &permanentlyBrokenCaptureReader{}
	processor := NewProcessor()
	err := processor.Process(reader, models.NewAnalysisState(), &models.TriageReport{}, nil)
	if err == nil {
		t.Fatal("persistent malformed records must not produce an infinite loop")
	}
	if reader.calls != 5 {
		t.Fatalf("reader calls = %d; want five bounded attempts", reader.calls)
	}
}
