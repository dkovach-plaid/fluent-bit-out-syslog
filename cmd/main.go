package main

import (
	"C"
	"encoding/json"
	"log"
	"time"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
	"github.com/pivotal-cf/fluent-bit-out-syslog/pkg/syslog"
)

var out *syslog.Out

//export FLBPluginRegister
func FLBPluginRegister(ctx unsafe.Pointer) int {
	return output.FLBPluginRegister(
		ctx,
		"syslog",
		"syslog output plugin that follows RFC 5424",
	)
}

//export FLBPluginInit
func FLBPluginInit(ctx unsafe.Pointer) int {
	s := output.FLBPluginConfigKey(ctx, "sinks")
	cs := output.FLBPluginConfigKey(ctx, "clustersinks")
	facility := strings.Title(output.FLBPluginConfigKey(ctx, "facility"))
	severity := strings.Title(output.FLBPluginConfigKey(ctx, "severity"))
	if s == "" && cs == "" {
		log.Println("[out_syslog] ERROR: sinks can't be empty")
		return output.FLB_ERROR
	}

	if facility == "" {
		facility = "User"
	}

	if severity == "" {
		severity = "Info"
	}

	log.Println("[out_syslog] sinks =", s)
	log.Println("[out_syslog] cluster sinks =", cs)

	var (
		sinks        []*syslog.Sink
		clusterSinks []*syslog.Sink
	)

	if len(s) != 0 {
		err := json.Unmarshal([]byte(s), &sinks)
		if err != nil {
			log.Printf("[out_syslog] unable to unmarshal sinks: %s", err)
			return output.FLB_ERROR
		}
	}
	if len(cs) != 0 {
		err := json.Unmarshal([]byte(cs), &clusterSinks)
		if err != nil {
			log.Printf("[out_syslog] unable to unmarshal cluster sinks: %s", err)
			return output.FLB_ERROR
		}
	}

	if len(sinks)+len(clusterSinks) == 0 {
		log.Println("[out_syslog] require at least one sink or cluster sink")
		return output.FLB_ERROR
	}
	out = syslog.NewOut(sinks, clusterSinks, facility, severity)
	return output.FLB_OK
}

//export FLBPluginFlush
func FLBPluginFlush(data unsafe.Pointer, length C.int, tag *C.char) int {
	var (
		ret    int
		ts     interface{}
		record map[interface{}]interface{}
	)

	dec := output.NewDecoder(data, int(length))
	for {
		ret, ts, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}

		var timestamp time.Time
		switch tts := ts.(type) {
		case output.FLBTime:
			timestamp = tts.Time
		case uint64:
			// From our observation, when ts is of type uint64 it appears to
			// be the amount of seconds since unix epoch.
			timestamp = time.Unix(int64(tts), 0)
		default:
			timestamp = time.Now()
		}

		err := out.Write(record, timestamp, C.GoString(tag))
		if err != nil {
			// TODO: switch over to FLB_RETRY when we are capable of retrying
			// TODO: how we know the flush keeps running issues.
			return output.FLB_ERROR
		}
	}

	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	// TODO: We should probably call conn.Close() for each sink connection
	return output.FLB_OK
}

func main() {
}
