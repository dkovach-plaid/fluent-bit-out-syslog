package syslog

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"code.cloudfoundry.org/rfc5424"
)

// TODO: Address issues where messages are malformed but we are not notifying
// the user.

type Sink struct {
	Addr      string `json:"addr"`
	Namespace string `json:"namespace"`
	TLS       *TLS   `json:"tls"`

	conn               net.Conn
	maintainConnection func() error
}

type TLS struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// Out writes fluentbit messages via syslog TCP (RFC 5424 and RFC 6587).
type Out struct {
	sinks        map[string][]*Sink
        facility     string
        severity     string
	clusterSinks []*Sink
	dialTimeout  time.Duration
}

type OutOption func(*Out)

func WithDialTimeout(d time.Duration) OutOption {
	return func(o *Out) {
		o.dialTimeout = d
	}
}

// NewOut returns a new Out which handles both tcp and tls connections.
func NewOut(sinks, facility, severity, clusterSinks []*Sink, opts ...OutOption) *Out {
	out := &Out{
		dialTimeout: 5 * time.Second,
		facility: facility,
		severity: severity,
	}

	m := make(map[string][]*Sink)
	for _, s := range sinks {
		if s.TLS != nil {
			s.maintainConnection = tlsMaintainConn(s, out)
		} else {
			s.maintainConnection = tcpMaintainConn(s, out)
		}

		m[s.Namespace] = append(m[s.Namespace], s)
	}
	for _, s := range clusterSinks {
		if s.TLS != nil {
			s.maintainConnection = tlsMaintainConn(s, out)
		} else {
			s.maintainConnection = tcpMaintainConn(s, out)
		}
	}
	out.sinks = m
	out.clusterSinks = clusterSinks

	for _, o := range opts {
		o(out)
	}

	return out
}

// Write takes a record, timestamp, and tag, converts it into a syslog message
// and routes it to the connection with the matching namespace. If there are
// no connections configured for a record's namespace, it drops the message.
// If no connection is established one will be established per sink upon a
// Write operation. If all sinks for a namespace fail to write, Write will
// return an error. Write will also write all messages to all cluster sinks
// provided.
func (o *Out) Write(
	record map[interface{}]interface{},
	ts time.Time,
	tag string,
        fac string,
        sev string,
) error {
	msg, namespace := convert(record, ts, tag, fac, sev)

	var errCount int
	for _, cs := range o.clusterSinks {
		if cs.write(msg) != nil {
			errCount++
		}
	}

	namespaceSinks, ok := o.sinks[namespace]
	if !ok {
		// TODO: track ignored messages
		return nil
	}

	for _, s := range namespaceSinks {
		if s.write(msg) != nil {
			errCount++
		}
	}

	if errCount == len(namespaceSinks)+len(o.clusterSinks) {
		return fmt.Errorf("failed to write to all sinks for namespace: %s", namespace)
	}
	return nil
}

// write writes a rfc5424 syslog message to the connection of the specified
// sink. It recreates the connection if one isn't established yet.
func (s *Sink) write(m *rfc5424.Message) error {
	err := s.maintainConnection()
	if err != nil {
		return err
	}

	_, err = m.WriteTo(s.conn)
	if err != nil {
		s.conn = nil
		return err
	}
	return nil
}

func tlsMaintainConn(s *Sink, out *Out) func() error {
	return func() error {
		if s.conn == nil {
			dialer := net.Dialer{
				Timeout: out.dialTimeout,
			}
			var conn net.Conn // conn needs to be of type net.Conn, not *tls.Conn
			conn, err := tls.DialWithDialer(
				&dialer,
				"tcp",
				s.Addr,
				&tls.Config{
					InsecureSkipVerify: s.TLS.InsecureSkipVerify,
				},
			)
			if err == nil {
				s.conn = conn
			}
			return err
		}
		return nil
	}
}

func tcpMaintainConn(s *Sink, out *Out) func() error {
	return func() error {
		dialer := net.Dialer{
			Timeout: out.dialTimeout,
		}
		if s.conn == nil {
			conn, err := dialer.Dial("tcp", s.Addr)
			s.conn = conn
			return err
		}
		return nil
	}
}

func convert(
	record map[interface{}]interface{},
	ts time.Time,
	tag string,
        fac string,
        sev string,
) (*rfc5424.Message, string) {
	var (
		logmsg []byte
		k8sMap map[interface{}]interface{}
	)

	for k, v := range record {
		key, ok := k.(string)
		if !ok {
			continue
		}

		switch key {
		case "log":
			v2, ok2 := v.([]byte)
			if !ok2 {
				continue
			}
			logmsg = v2
		case "kubernetes":
			v2, ok2 := v.(map[interface{}]interface{})
			if !ok2 {
				continue
			}
			k8sMap = v2
		}
	}

	var (
		host          string
		appName       string
		podName       string
		namespaceName string
		containerName string
	)
	for k, v := range k8sMap {
		key, ok := k.(string)
		if !ok {
			continue
		}

		switch key {
		case "host":
			v2, ok2 := v.([]byte)
			if !ok2 {
				continue
			}
			host = string(v2)
		case "container_name":
			v2, ok2 := v.([]byte)
			if !ok2 {
				continue
			}
			containerName = string(v2)
		case "pod_name":
			v2, ok2 := v.([]byte)
			if !ok2 {
				continue
			}
			podName = string(v2)
		case "namespace_name":
			v2, ok2 := v.([]byte)
			if !ok2 {
				continue
			}
			namespaceName = string(v2)
		}
	}

	if len(k8sMap) != 0 {
		// sample: kube-system/pod/kube-dns-86f4d74b45-lfgj7/dnsmasq
		appName = fmt.Sprintf(
			"%s/%s/%s",
			namespaceName,
			podName,
			containerName,
		)
		// APP-NAME is limited to 48 chars in RFC 5424
		// https://tools.ietf.org/html/rfc5424#section-6
		if len(appName) > 48 {
			appName = appName[:48]
		}
	}

	if !bytes.HasSuffix(logmsg, []byte("\n")) {
		logmsg = append(logmsg, byte('\n'))
	}

	// map out all the facility and severity names -> numeric values
	facilities := map[string]rfc5424.Priority{
		"User": rfc5424.User,
		"Mail": rfc5424.Mail,
		"Daemon": rfc5424.Daemon,
		"Auth": rfc5424.Auth,
		"Syslog": rfc5424.Syslog,
		"Lpr": rfc5424.Lpr,
		"News": rfc5424.News,
		"Uucp": rfc5424.Uucp,
		"Cron": rfc5424.Cron,
		"Authpriv": rfc5424.Authpriv,
		"Ftp": rfc5424.Ftp,
		"Local0": rfc5424.Local0,
		"Local1": rfc5424.Local1,
		"Local2": rfc5424.Local2,
		"Local3": rfc5424.Local3,
		"Local4": rfc5424.Local4,
		"Local5": rfc5424.Local5,
		"Local6": rfc5424.Local6,
		"Local7": rfc5424.Local7,
	}

	severities := map[string]rfc5424.Priority{
		"Alert": rfc5424.Alert,
		"Crit": rfc5424.Crit,
		"Error": rfc5424.Error,
		"Warning": rfc5424.Warning,
		"Notice": rfc5424.Notice,
		"Info": rfc5424.Info,
		"Debug": rfc5424.Debug,
	}

	return &rfc5424.Message{
		Priority:  facilities[fac] + severities[sev],
		Timestamp: ts,
		Hostname:  host,
		AppName:   appName,
		Message:   logmsg,
		StructuredData: []rfc5424.StructuredData{
			{
				ID: "kubernetes@47450",
				Parameters: []rfc5424.SDParam{
					{
						Name:  "namespace_name",
						Value: namespaceName,
					},
					{
						Name:  "object_name",
						Value: podName,
					},
					{
						Name:  "container_name",
						Value: containerName,
					},
				},
			},
		},
	}, namespaceName
}
