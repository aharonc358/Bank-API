package models

// LogEntry represents the structure of a log entry for requests and responses.
type LogEntry struct {
	Req RequestLog  `json:"request"`
	Rsp ResponseLog `json:"response"`
}

// RequestLog contains details about the HTTP request.
type RequestLog struct {
	URL        string `json:"url"`
	QSParams   string `json:"query_string_params"`
	Headers    string `json:"headers"`
	ReqBodyLen int64  `json:"request_body_length"`
}

// ResponseLog contains details about the HTTP response.
type ResponseLog struct {
	StatusClass string `json:"status_class"`
	RspBodyLen  int    `json:"response_body_length"`
}
