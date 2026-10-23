package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func usersCmd() *cobra.Command {
	root := &cobra.Command{Use: "users", Short: "Manage local accounts (setup credentials are printed once; store privately)"}
	root.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return usersRequest(cmd, http.MethodGet, "/api/v1/local-users", nil)
	}})
	var email, name, role string
	var passwordStdin bool
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, Short: "Create an account and return password and TOTP enrollment once", RunE: func(cmd *cobra.Command, _ []string) error {
		password := ""
		if passwordStdin {
			var err error
			password, err = readUserPassword(cmd)
			if err != nil {
				return err
			}
		}
		return usersRequest(cmd, http.MethodPost, "/api/v1/local-users", map[string]string{"email": email, "display_name": name, "role": role, "password": password})
	}}
	create.Flags().StringVar(&email, "email", "", "Account email")
	_ = create.MarkFlagRequired("email")
	create.Flags().StringVar(&name, "name", "", "Display name")
	create.Flags().StringVar(&role, "role", "Analyst", "Product role")
	create.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read a password from stdin (otherwise generate)")
	root.AddCommand(create)
	for _, action := range []string{"disable", "reset-password", "reset-totp"} {
		var stdin bool
		c := &cobra.Command{Use: action + " <user-id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{}
			if stdin {
				password, err := readUserPassword(cmd)
				if err != nil {
					return err
				}
				body["password"] = password
			}
			return usersRequest(cmd, http.MethodPost, "/api/v1/local-users/"+url.PathEscape(args[0])+"/"+action, body)
		}}
		if action == "reset-password" {
			c.Flags().BoolVar(&stdin, "password-stdin", false, "Read a password from stdin (otherwise generate)")
		}
		root.AddCommand(c)
	}
	return root
}
func readUserPassword(cmd *cobra.Command) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4098))
	if err != nil {
		return "", err
	}
	password := strings.TrimSuffix(string(raw), "\n")
	if len(password) == 0 || len(password) > 4096 {
		return "", fmt.Errorf("password must contain 1–4096 bytes")
	}
	return password, nil
}
func usersRequest(cmd *cobra.Command, method, path string, body any) error {
	raw, err := apiCall(cmd.Context(), method, path, body)
	if err != nil {
		return err
	}
	var out any
	if err = json.Unmarshal(raw, &out); err != nil {
		return err
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
