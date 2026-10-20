package apiutil

// ConnectCode mirrors connectrpc.com/connect.Code (identical to the gRPC
// status numbers) so the Phase 2 interceptors can convert without a second
// table: connect.Code(apiutil.ToConnect(err)). Kept as an int here so this
// package has no RPC dependency until the Connect surface lands.
type ConnectCode uint32

const (
	ConnectCanceled           ConnectCode = 1
	ConnectUnknown            ConnectCode = 2
	ConnectInvalidArgument    ConnectCode = 3
	ConnectDeadlineExceeded   ConnectCode = 4
	ConnectNotFound           ConnectCode = 5
	ConnectAlreadyExists      ConnectCode = 6
	ConnectPermissionDenied   ConnectCode = 7
	ConnectResourceExhausted  ConnectCode = 8
	ConnectFailedPrecondition ConnectCode = 9
	ConnectAborted            ConnectCode = 10
	ConnectOutOfRange         ConnectCode = 11
	ConnectUnimplemented      ConnectCode = 12
	ConnectInternal           ConnectCode = 13
	ConnectUnavailable        ConnectCode = 14
	ConnectDataLoss           ConnectCode = 15
	ConnectUnauthenticated    ConnectCode = 16
)

var connectCodes = map[Code]ConnectCode{
	CodeCanceled: ConnectCanceled, CodeUnknown: ConnectUnknown, CodeInvalidArgument: ConnectInvalidArgument,
	CodeDeadlineExceeded: ConnectDeadlineExceeded, CodeNotFound: ConnectNotFound, CodeAlreadyExists: ConnectAlreadyExists,
	CodePermissionDenied: ConnectPermissionDenied, CodeResourceExhausted: ConnectResourceExhausted,
	CodeFailedPrecondition: ConnectFailedPrecondition, CodeAborted: ConnectAborted, CodeOutOfRange: ConnectOutOfRange,
	CodeUnimplemented: ConnectUnimplemented, CodeInternal: ConnectInternal, CodeUnavailable: ConnectUnavailable,
	CodeDataLoss: ConnectDataLoss, CodeUnauthenticated: ConnectUnauthenticated,
}

// ToConnect maps err to (connect code, client-safe message). Internal causes
// are scrubbed exactly as WriteError does for REST.
func ToConnect(err error) (ConnectCode, string) {
	code := CodeOf(err)
	cc, ok := connectCodes[code]
	if !ok {
		cc = ConnectInternal
	}
	message := clientMessage(err, code)
	if cc == ConnectInternal || cc == ConnectUnknown || cc == ConnectDataLoss {
		message = InternalMessage
	}
	return cc, message
}
