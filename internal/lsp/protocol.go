package lsp

import "encoding/json"

// The subset of LSP 3.18 types this server uses. Features newer than 3.16
// (snippet edits, markup diagnostic messages, command tooltips) are only used
// when the client advertises them, so 3.17 clients keep working. Positions
// are 0-based UTF-16 offsets, the protocol default; the server only produces
// line-granular ranges, so no offset conversion is needed beyond line lengths.

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type lspRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

type textDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type versionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type didChangeParams struct {
	TextDocument   versionedTextDocumentIdentifier `json:"textDocument"`
	ContentChanges []struct {
		// Full sync only: the server advertises TextDocumentSyncKind.Full.
		Text string `json:"text"`
	} `json:"contentChanges"`
}

type didCloseParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type textDocumentPositionParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Position     position               `json:"position"`
}

type workspaceFolder struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

// clientCapabilities holds the few capabilities the server branches on.
type clientCapabilities struct {
	Workspace struct {
		WorkspaceEdit struct {
			DocumentChanges    bool `json:"documentChanges"`
			SnippetEditSupport bool `json:"snippetEditSupport"`
		} `json:"workspaceEdit"`
	} `json:"workspace"`
	Window struct {
		ShowDocument struct {
			Support bool `json:"support"`
		} `json:"showDocument"`
	} `json:"window"`
}

type initializeParams struct {
	ProcessID *int `json:"processId"`
	// RootURI is deprecated in favour of WorkspaceFolders; read as a fallback.
	RootURI               string             `json:"rootUri"`
	Capabilities          clientCapabilities `json:"capabilities"`
	WorkspaceFolders      []workspaceFolder  `json:"workspaceFolders"`
	InitializationOptions json.RawMessage    `json:"initializationOptions"`
	ClientInfo            *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"clientInfo"`
}

// Diagnostic severities.
const (
	severityError       = 1
	severityWarning     = 2
	severityInformation = 3
	severityHint        = 4
)

// Diagnostic tags.
const tagUnnecessary = 1

type codeDescription struct {
	Href string `json:"href"`
}

type diagnostic struct {
	Range           lspRange         `json:"range"`
	Severity        int              `json:"severity"`
	Code            string           `json:"code,omitempty"`
	CodeDescription *codeDescription `json:"codeDescription,omitempty"`
	Source          string           `json:"source"`
	Message         string           `json:"message"`
	Tags            []int            `json:"tags,omitempty"`
	// Data carries the finding fingerprint so code actions can find it again
	// without matching messages.
	Data *diagnosticData `json:"data,omitempty"`
}

type diagnosticData struct {
	Fingerprint string `json:"fingerprint"`
}

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     *int         `json:"version,omitempty"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

type markupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type hover struct {
	Contents markupContent `json:"contents"`
	Range    *lspRange     `json:"range,omitempty"`
}

type codeActionParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Range        lspRange               `json:"range"`
	Context      struct {
		Diagnostics []diagnostic `json:"diagnostics"`
	} `json:"context"`
}

type textEdit struct {
	Range   lspRange `json:"range"`
	NewText string   `json:"newText"`
}

type workspaceEdit struct {
	Changes         map[string][]textEdit `json:"changes,omitempty"`
	DocumentChanges []textDocumentEdit    `json:"documentChanges,omitempty"`
}

// textDocumentEdit carries SnippetTextEdits (LSP 3.18), which only the
// documentChanges form of a WorkspaceEdit can hold.
type textDocumentEdit struct {
	TextDocument optionalVersionedTextDocumentIdentifier `json:"textDocument"`
	Edits        []snippetTextEdit                       `json:"edits"`
}

type optionalVersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version *int   `json:"version"`
}

type stringValue struct {
	Kind  string `json:"kind"` // always "snippet"
	Value string `json:"value"`
}

type snippetTextEdit struct {
	Range   lspRange    `json:"range"`
	Snippet stringValue `json:"snippet"`
}

type command struct {
	Title     string `json:"title"`
	Tooltip   string `json:"tooltip,omitempty"` // LSP 3.18
	Command   string `json:"command"`
	Arguments []any  `json:"arguments,omitempty"`
}

type codeAction struct {
	Title       string         `json:"title"`
	Kind        string         `json:"kind"`
	Diagnostics []diagnostic   `json:"diagnostics,omitempty"`
	IsPreferred bool           `json:"isPreferred,omitempty"`
	Edit        *workspaceEdit `json:"edit,omitempty"`
	Command     *command       `json:"command,omitempty"`
}

type executeCommandParams struct {
	Command   string            `json:"command"`
	Arguments []json.RawMessage `json:"arguments"`
}

type showDocumentParams struct {
	URI       string `json:"uri"`
	External  bool   `json:"external,omitempty"`
	TakeFocus bool   `json:"takeFocus,omitempty"`
}

// Message types for window/showMessage and window/logMessage.
const (
	messageError   = 1
	messageWarning = 2
	messageInfo    = 3
	messageLog     = 4
)

type showMessageParams struct {
	Type    int    `json:"type"`
	Message string `json:"message"`
}
