package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
)

// The incident CLI (ADR-053 §11): the whole process can be driven from a
// runbook. Every command maps onto one API call; hibou keeps the clocks,
// derives the actions and records the evidence.

var incidentCmd = &cobra.Command{
	Use:   "incident",
	Short: "Open, decide, deliver and export incidents (CRA Article 14 and others)",
	Long: `Incidents bind a signal (an exploited vulnerability, a leaked secret, a
malicious package, a policy breach or a declared security incident) to the
versions and clients it affects, derive the actions it requires, keep the
regulatory clocks, and close themselves when nothing remains.

  hibou incident list
  hibou incident status 12
  hibou incident decide 12 --state reportable --step attacked --reason "customer evidence"
  hibou incident action 12 <action-id> file --reference SRP-2026-0042
  hibou incident deliver 12 --client acme --measures "upgrade to 4.2.2"
  hibou incident export 12 -o incident-12.zip`,
}

type cliIncident struct {
	ID           string     `json:"id"`
	Number       int        `json:"number"`
	Title        string     `json:"title"`
	Kind         string     `json:"kind"`
	KindLabel    string     `json:"kind_label"`
	State        string     `json:"state"`
	Priority     string     `json:"priority"`
	Regimes      []string   `json:"regimes"`
	RepoSlug     string     `json:"repo_slug"`
	SignalSource string     `json:"signal_source"`
	SignalAt     time.Time  `json:"signal_at"`
	AwareAt      *time.Time `json:"aware_at"`
	DueAt        *time.Time `json:"due_at"`
}

func incidentPath(org string, number string, suffix string) string {
	return fmt.Sprintf("/orgs/%s/incidents/%s%s", org, url.PathEscape(number), suffix)
}

func incidentClient() (*cliclient.Client, string, error) {
	client, err := cliclient.New()
	if err != nil {
		return nil, "", err
	}
	org, err := resolveOrg()
	return client, org, err
}

func requireIncidentNumber(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("the incident number is required")
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(args[0], "#")); err != nil {
		return "", fmt.Errorf("%q is not an incident number", args[0])
	}
	return strings.TrimPrefix(args[0], "#"), nil
}

func formatDue(due *time.Time) string {
	if due == nil {
		return "-"
	}
	left := time.Until(*due).Round(time.Minute)
	if left < 0 {
		return "overdue " + (-left).String()
	}
	return "in " + left.String()
}

var incidentListState, incidentListKind, incidentListRepo string

var incidentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List incidents, nearest deadline first",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		query := url.Values{"per_page": {"100"}}
		if incidentListState != "all" {
			query.Set("state", incidentListState)
		}
		if incidentListKind != "" {
			query.Set("kind", incidentListKind)
		}
		if incidentListRepo != "" {
			query.Set("repo", incidentListRepo)
		}
		var incidents []cliIncident
		if err := client.Get(fmt.Sprintf("/orgs/%s/incidents?%s", org, query.Encode()), &incidents); err != nil {
			return err
		}
		if len(incidents) == 0 {
			fmt.Println("No incidents.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "#\tPRIORITY\tSTATE\tKIND\tREPO\tNEXT DUE\tTITLE")
		for _, inc := range incidents {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", inc.Number, inc.Priority, inc.State, inc.KindLabel, firstNonEmptyCLI(inc.RepoSlug, "-"), formatDue(inc.DueAt), inc.Title)
		}
		return w.Flush()
	},
}

var incidentStatusCmd = &cobra.Command{
	Use:     "status <number>",
	Aliases: []string{"show"},
	Short:   "Show an incident: clocks, scope, actions, deliveries",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		var detail struct {
			Incident  cliIncident `json:"incident"`
			Deadlines []struct {
				Regime    string     `json:"regime"`
				Step      string     `json:"step"`
				DueAt     time.Time  `json:"due_at"`
				MetAt     *time.Time `json:"met_at"`
				Reference string     `json:"reference"`
			} `json:"deadlines"`
			Scope []struct {
				SubjectType string `json:"subject_type"`
				Label       string `json:"label"`
				Status      string `json:"status"`
				Reason      string `json:"reason"`
				Clients     []struct {
					Name string `json:"name"`
				} `json:"clients"`
			} `json:"scope"`
			Actions []struct {
				ID       string     `json:"id"`
				Kind     string     `json:"kind"`
				Label    string     `json:"label"`
				State    string     `json:"state"`
				Obsolete bool       `json:"obsolete"`
				Optional bool       `json:"optional"`
				DueAt    *time.Time `json:"due_at"`
			} `json:"actions"`
			Deliveries []struct {
				ClientName *string `json:"client_name"`
				Channel    string  `json:"channel"`
				Status     string  `json:"status"`
			} `json:"deliveries"`
		}
		if err := client.Get(incidentPath(org, number, ""), &detail); err != nil {
			return err
		}
		inc := detail.Incident
		fmt.Printf("#%d %s\n%s · %s · %s · regimes %s\n", inc.Number, inc.Title, inc.KindLabel, inc.State, inc.Priority, strings.Join(inc.Regimes, ", "))
		if inc.AwareAt != nil {
			fmt.Printf("T0 %s\n", inc.AwareAt.UTC().Format(time.RFC3339))
		}
		if len(detail.Deadlines) > 0 {
			fmt.Println("\nClocks:")
			for _, deadline := range detail.Deadlines {
				state := formatDue(&deadline.DueAt)
				if deadline.MetAt != nil {
					state = "met " + deadline.MetAt.UTC().Format(time.RFC3339) + " " + deadline.Reference
				}
				fmt.Printf("  %-16s %-14s %s\n", deadline.Regime, deadline.Step, state)
			}
		}
		if len(detail.Scope) > 0 {
			fmt.Println("\nScope:")
			for _, row := range detail.Scope {
				clients := make([]string, 0, len(row.Clients))
				for _, client := range row.Clients {
					clients = append(clients, client.Name)
				}
				fmt.Printf("  %-8s %-14s %-12s %s %s\n", row.SubjectType, row.Label, row.Status, strings.Join(clients, ", "), row.Reason)
			}
		}
		fmt.Println("\nActions:")
		for _, action := range detail.Actions {
			if action.Obsolete {
				continue
			}
			marker := "[ ]"
			switch action.State {
			case "done":
				marker = "[x]"
			case "waived":
				marker = "[~]"
			}
			optional := ""
			if action.Optional {
				optional = " (optional)"
			}
			fmt.Printf("  %s %s%s  due %s  id %s\n", marker, action.Label, optional, formatDue(action.DueAt), action.ID)
		}
		if len(detail.Deliveries) > 0 {
			fmt.Println("\nDeliveries:")
			for _, delivery := range detail.Deliveries {
				name := "-"
				if delivery.ClientName != nil {
					name = *delivery.ClientName
				}
				fmt.Printf("  %-20s %-8s %s\n", name, delivery.Channel, delivery.Status)
			}
		}
		return nil
	},
}

var (
	incidentOpenKind, incidentOpenRepo, incidentOpenTitle, incidentOpenVuln, incidentOpenFinding string
	incidentOpenSource, incidentOpenPriority, incidentOpenNote                                   string
	incidentOpenRegimes, incidentOpenReleases, incidentOpenClients                               []string
)

var incidentOpenCmd = &cobra.Command{
	Use:   "open",
	Short: "Open an incident from a signal (customer, CSIRT, researcher, internal)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		body := map[string]any{
			"kind": incidentOpenKind, "repo_slug": incidentOpenRepo, "title": incidentOpenTitle, "vulnerability_id": incidentOpenVuln,
			"finding_id": incidentOpenFinding, "signal_source": incidentOpenSource, "priority": incidentOpenPriority,
			"regimes": incidentOpenRegimes, "release_ids": incidentOpenReleases, "client_ids": incidentOpenClients, "note": incidentOpenNote,
		}
		var created cliIncident
		if err := client.Post(fmt.Sprintf("/orgs/%s/incidents", org), body, &created); err != nil {
			return err
		}
		fmt.Printf("Opened incident #%d: %s\n", created.Number, created.Title)
		return nil
	},
}

var incidentDecideState, incidentDecideReason, incidentDecideStep, incidentDecideAware, incidentDecideJustification, incidentDecideAction string
var incidentDecideNoVEX bool

var incidentDecideCmd = &cobra.Command{
	Use:   "decide <number>",
	Short: "Record the decision: reportable or not (confirmed or dismissed), with its reason and T0",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		body := map[string]any{"state": incidentDecideState, "reason": incidentDecideReason, "decision_step": incidentDecideStep, "write_statements": !incidentDecideNoVEX}
		if incidentDecideJustification != "" {
			body["justification"] = incidentDecideJustification
		}
		if incidentDecideAction != "" {
			body["action_statement"] = incidentDecideAction
		}
		if incidentDecideAware != "" {
			aware, err := time.Parse(time.RFC3339, incidentDecideAware)
			if err != nil {
				return fmt.Errorf("--aware-at: %w", err)
			}
			body["aware_at"] = aware
		}
		var inc cliIncident
		if err := client.Post(incidentPath(org, number, "/decide"), body, &inc); err != nil {
			return err
		}
		if inc.State != incidentDecideState {
			fmt.Printf("Decision proposed on #%d; another person approves it (hibou incident approve %s).\n", inc.Number, number)
			return nil
		}
		fmt.Printf("#%d is %s.\n", inc.Number, inc.State)
		return nil
	},
}

var incidentApproveCmd = &cobra.Command{
	Use:   "approve <number>",
	Short: "Approve a decision someone else proposed (four-eyes)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		var inc cliIncident
		if err := client.Post(incidentPath(org, number, "/decision/approve"), map[string]any{}, &inc); err != nil {
			return err
		}
		fmt.Printf("#%d is %s.\n", inc.Number, inc.State)
		return nil
	},
}

var (
	incidentScopeRelease, incidentScopeStatus, incidentScopeReason string
	incidentScopeClear                                             bool
)

var incidentScopeCmd = &cobra.Command{
	Use:   "scope <number>",
	Short: "Exclude a release from the scope (with a reason), or hand it back to derivation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		if incidentScopeRelease == "" {
			return errors.New("--release is required (a release id from 'hibou incident status')")
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		body := map[string]any{"subject_type": "release", "subject_id": incidentScopeRelease, "status": incidentScopeStatus, "reason": incidentScopeReason, "clear": incidentScopeClear}
		if err := client.Post(incidentPath(org, number, "/scope"), body, nil); err != nil {
			return err
		}
		fmt.Println("Scope updated.")
		return nil
	},
}

var incidentActionNote, incidentActionReference, incidentActionReason, incidentActionFiledAt string

var incidentActionCmd = &cobra.Command{
	Use:   "action <number> <action-id> complete|file|waive|reopen",
	Short: "Complete, file, waive or reopen an action",
	Long: `complete   a manual action, with --note or --reference as evidence
file       a filing on the authority's platform, with --reference (and --filed-at)
waive      the sanctioned exception, with --reason (four-eyes when configured)
reopen     with --reason`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		op := args[2]
		switch op {
		case "complete", "file", "waive", "reopen":
		default:
			return fmt.Errorf("unknown operation %q", op)
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		body := map[string]any{"note": incidentActionNote, "reference": incidentActionReference, "reason": incidentActionReason}
		if incidentActionFiledAt != "" {
			filedAt, err := time.Parse(time.RFC3339, incidentActionFiledAt)
			if err != nil {
				return fmt.Errorf("--filed-at: %w", err)
			}
			body["filed_at"] = filedAt
		}
		var action struct {
			Label string `json:"label"`
			State string `json:"state"`
		}
		if err := client.Post(incidentPath(org, number, "/actions/"+url.PathEscape(args[1])+"/"+op), body, &action); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", action.Label, action.State)
		return nil
	},
}

var (
	incidentDeliverClients                                                   []string
	incidentDeliverChannel, incidentDeliverMeasures, incidentDeliverEvidence string
)

var incidentDeliverCmd = &cobra.Command{
	Use:   "deliver <number>",
	Short: "Send the client notice (CSAF advisory, VEX, readable notice) to clients",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		if len(incidentDeliverClients) == 0 {
			return errors.New("--client is required (slug or id, repeatable)")
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(incidentDeliverClients))
		for _, ref := range incidentDeliverClients {
			var found struct {
				ID string `json:"id"`
			}
			if err := client.Get(fmt.Sprintf("/orgs/%s/clients/%s", org, url.PathEscape(ref)), &found); err == nil && found.ID != "" {
				ids = append(ids, found.ID)
				continue
			}
			ids = append(ids, ref)
		}
		var deliveries []struct {
			ID        string `json:"id"`
			Recipient string `json:"recipient"`
			Channel   string `json:"channel"`
			Status    string `json:"status"`
			Error     string `json:"error"`
		}
		body := map[string]any{"client_ids": ids, "channel": incidentDeliverChannel, "measures": incidentDeliverMeasures, "evidence": incidentDeliverEvidence}
		if err := client.Post(incidentPath(org, number, "/deliveries"), body, &deliveries); err != nil {
			return err
		}
		for _, delivery := range deliveries {
			line := fmt.Sprintf("%s → %s by %s: %s", delivery.ID, delivery.Recipient, delivery.Channel, delivery.Status)
			if delivery.Error != "" {
				line += " (" + delivery.Error + ")"
			}
			fmt.Println(line)
		}
		return nil
	},
}

var incidentExportOutput string

var incidentExportCmd = &cobra.Command{
	Use:   "export <number>",
	Short: "Download the incident dossier (timeline, scope, actions, deliveries, documents)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		stream, err := client.GetStream(incidentPath(org, number, "/dossier"), "application/zip")
		if err != nil {
			return err
		}
		defer stream.Close()
		output := incidentExportOutput
		if output == "" {
			output = "incident-" + number + ".zip"
		}
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the user names the output file
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := io.Copy(file, stream); err != nil {
			return err
		}
		fmt.Println("Wrote " + output)
		return nil
	},
}

var incidentDraftStep string

var incidentDraftCmd = &cobra.Command{
	Use:   "filing-draft <number>",
	Short: "Print the pre-filled content of a filing, to copy onto the authority's platform",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		var draft struct {
			Text string `json:"text"`
		}
		if err := client.Get(incidentPath(org, number, "/filing-draft?step="+url.QueryEscape(incidentDraftStep)), &draft); err != nil {
			return err
		}
		fmt.Print(draft.Text)
		return nil
	},
}

var incidentWithdrawReason, incidentFixAt, incidentFixNote string

var incidentWithdrawCmd = &cobra.Command{
	Use:   "withdraw <number>",
	Short: "Withdraw an incident that should not exist (wrong subject, duplicate)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		if err := client.Post(incidentPath(org, number, "/withdraw"), map[string]any{"reason": incidentWithdrawReason}, nil); err != nil {
			return err
		}
		fmt.Printf("#%s withdrawn.\n", number)
		return nil
	},
}

var incidentFixCmd = &cobra.Command{
	Use:   "fix-available <number>",
	Short: "Record that a corrective measure is available (starts the final-report clock)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		body := map[string]any{"note": incidentFixNote}
		if incidentFixAt != "" {
			at, err := time.Parse(time.RFC3339, incidentFixAt)
			if err != nil {
				return fmt.Errorf("--at: %w", err)
			}
			body["at"] = at
		}
		if err := client.Post(incidentPath(org, number, "/fix-available"), body, nil); err != nil {
			return err
		}
		fmt.Println("Recorded.")
		return nil
	},
}

var verifyDocumentCmd = &cobra.Command{
	Use:   "verify-document <incident-number> <delivery-id>",
	Short: "Re-render a delivery's documents from their recorded inputs and compare with what was sent",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		number, err := requireIncidentNumber(args)
		if err != nil {
			return err
		}
		client, org, err := incidentClient()
		if err != nil {
			return err
		}
		var result struct {
			Verified  bool             `json:"verified"`
			Documents []map[string]any `json:"documents"`
		}
		if err := client.Post(incidentPath(org, number, "/deliveries/"+url.PathEscape(args[1])+"/verify"), map[string]any{}, &result); err != nil {
			return err
		}
		for _, doc := range result.Documents {
			line, _ := json.Marshal(doc)
			fmt.Println(string(line))
		}
		if !result.Verified {
			return errors.New("verification failed: a stored document does not match its digest or its re-rendering")
		}
		fmt.Println("Every document matches its digest and re-renders byte for byte.")
		return nil
	},
}

func init() {
	incidentListCmd.Flags().StringVar(&incidentListState, "state", "open", "open, closed, all, or a state")
	incidentListCmd.Flags().StringVar(&incidentListKind, "kind", "", "incident kind")
	incidentListCmd.Flags().StringVar(&incidentListRepo, "repo", "", "repository slug")

	incidentOpenCmd.Flags().StringVar(&incidentOpenKind, "kind", "", "exploited_vulnerability, severe_incident, secret_leak, malware or policy_breach (required)")
	incidentOpenCmd.Flags().StringVar(&incidentOpenRepo, "repo", "", "repository slug")
	incidentOpenCmd.Flags().StringVar(&incidentOpenTitle, "title", "", "title")
	incidentOpenCmd.Flags().StringVar(&incidentOpenVuln, "vulnerability", "", "advisory identifier, for an exploited vulnerability")
	incidentOpenCmd.Flags().StringVar(&incidentOpenFinding, "finding", "", "finding id, for secret, malware and policy incidents")
	incidentOpenCmd.Flags().StringVar(&incidentOpenSource, "signal", "internal", "customer, csirt, researcher, internal, other")
	incidentOpenCmd.Flags().StringVar(&incidentOpenPriority, "priority", "P2", "P1, P2 or P3")
	incidentOpenCmd.Flags().StringVar(&incidentOpenNote, "note", "", "a first note for the timeline")
	incidentOpenCmd.Flags().StringSliceVar(&incidentOpenRegimes, "regime", nil, "cra-article-14, nis2-article-23, national:<code>, internal (repeatable)")
	incidentOpenCmd.Flags().StringSliceVar(&incidentOpenReleases, "release", nil, "release id in scope, for a security incident (repeatable)")
	incidentOpenCmd.Flags().StringSliceVar(&incidentOpenClients, "client", nil, "client id in scope, for a security incident (repeatable)")
	_ = incidentOpenCmd.MarkFlagRequired("kind")

	incidentDecideCmd.Flags().StringVar(&incidentDecideState, "state", "", "reportable, not_reportable, confirmed or dismissed (required)")
	incidentDecideCmd.Flags().StringVar(&incidentDecideReason, "reason", "", "the reason (required)")
	incidentDecideCmd.Flags().StringVar(&incidentDecideStep, "step", "", "ladder step of an exploited vulnerability: not_present, not_reachable (cannot be exploited here), reachable_no_attack (not exploited here) or attacked (exploited here: reportable)")
	incidentDecideCmd.Flags().StringVar(&incidentDecideAware, "aware-at", "", "T0, RFC 3339 (default: now)")
	incidentDecideCmd.Flags().StringVar(&incidentDecideJustification, "justification", "", "VEX justification for not_reachable: vulnerable_code_not_in_execute_path (default), vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist, vulnerable_code_not_present")
	incidentDecideCmd.Flags().StringVar(&incidentDecideAction, "action", "", "VEX action statement for an affected step: what users can do")
	incidentDecideCmd.Flags().BoolVar(&incidentDecideNoVEX, "no-vex", false, "Do not record the step as the VEX statement of the releases in scope without one")

	incidentScopeCmd.Flags().StringVar(&incidentScopeRelease, "release", "", "release id")
	incidentScopeCmd.Flags().StringVar(&incidentScopeStatus, "status", "excluded", "excluded or affected")
	incidentScopeCmd.Flags().StringVar(&incidentScopeReason, "reason", "", "the reason")
	incidentScopeCmd.Flags().BoolVar(&incidentScopeClear, "clear", false, "hand the row back to derivation")

	incidentActionCmd.Flags().StringVar(&incidentActionNote, "note", "", "evidence note")
	incidentActionCmd.Flags().StringVar(&incidentActionReference, "reference", "", "reference (ticket, platform filing)")
	incidentActionCmd.Flags().StringVar(&incidentActionReason, "reason", "", "reason (waive, reopen)")
	incidentActionCmd.Flags().StringVar(&incidentActionFiledAt, "filed-at", "", "when the filing was made, RFC 3339 (default: now)")

	incidentDeliverCmd.Flags().StringSliceVar(&incidentDeliverClients, "client", nil, "client slug or id (repeatable)")
	incidentDeliverCmd.Flags().StringVar(&incidentDeliverChannel, "channel", "", "email, webhook, portal or manual (default: the client's)")
	incidentDeliverCmd.Flags().StringVar(&incidentDeliverMeasures, "measures", "", "what clients should do: workaround or fix")
	incidentDeliverCmd.Flags().StringVar(&incidentDeliverEvidence, "evidence", "", "how a manual delivery was made")

	incidentExportCmd.Flags().StringVarP(&incidentExportOutput, "output", "o", "", "output file (default incident-<n>.zip)")
	incidentDraftCmd.Flags().StringVar(&incidentDraftStep, "step", "early_warning", "early_warning, notification or final_report")
	incidentWithdrawCmd.Flags().StringVar(&incidentWithdrawReason, "reason", "", "the reason (required)")
	incidentFixCmd.Flags().StringVar(&incidentFixAt, "at", "", "when the measure became available, RFC 3339 (default: now)")
	incidentFixCmd.Flags().StringVar(&incidentFixNote, "note", "", "what the measure is")

	incidentCmd.AddCommand(incidentListCmd, incidentStatusCmd, incidentOpenCmd, incidentDecideCmd, incidentApproveCmd, incidentScopeCmd,
		incidentActionCmd, incidentDeliverCmd, incidentExportCmd, incidentDraftCmd, incidentWithdrawCmd, incidentFixCmd)
}
