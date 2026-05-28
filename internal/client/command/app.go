// Пакет command реализует пользовательские сценарии CLI-клиента GophKeeper.
package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajgultumerkina/gophkeeper/internal/buildinfo"
	clientapi "github.com/ajgultumerkina/gophkeeper/internal/client/api"
	vaultcrypto "github.com/ajgultumerkina/gophkeeper/internal/client/crypto"
	"github.com/ajgultumerkina/gophkeeper/internal/client/otp"
	"github.com/ajgultumerkina/gophkeeper/internal/client/session"
	"github.com/ajgultumerkina/gophkeeper/internal/protocol"
	"github.com/spf13/cobra"
)

// PasswordReader читает чувствительные данные из терминала без отображения
// введённых символов.
type PasswordReader func(prompt string) (string, error)

type remote interface {
	Register(context.Context, protocol.RegisterRequest) error
	LoginParameters(context.Context, string) (protocol.LoginParametersResponse, error)
	Login(context.Context, protocol.LoginRequest) (protocol.LoginResponse, error)
	Refresh(context.Context, string) (protocol.TokenPair, error)
	Logout(context.Context, string) error
	GetItem(context.Context, string, string) (protocol.EncryptedItem, error)
	PutItem(context.Context, string, protocol.EncryptedItem, int64) (protocol.EncryptedItem, error)
	DeleteItem(context.Context, string, string, int64) (protocol.EncryptedItem, error)
	Sync(context.Context, string, int64) (protocol.SyncResponse, error)
}

// App хранит потоки ввода-вывода и запускает подкоманды CLI.
type App struct {
	input       *bufio.Reader
	output      io.Writer
	errors      io.Writer
	password    PasswordReader
	sessionPath string
	newRemote   func(string) (remote, error)
}

type addOptions struct {
	kind     vaultcrypto.Kind
	name     string
	metadata string
	file     string
	uri      string
}

// New создаёт CLI-приложение с переданными потоками терминала и путём к файлу
// локальной сессии.
func New(input io.Reader, output, errorOutput io.Writer, password PasswordReader, sessionPath string) *App {
	return &App{
		input:       bufio.NewReader(input),
		output:      output,
		errors:      errorOutput,
		password:    password,
		sessionPath: sessionPath,
		newRemote: func(server string) (remote, error) {
			return clientapi.New(server, &http.Client{Timeout: 30 * time.Second})
		},
	}
}

// Run выполняет одну CLI-команду и возвращает ошибку, которую можно показать в
// терминале пользователю.
func (a *App) Run(ctx context.Context, args []string) error {
	cmd := a.rootCommand(ctx)
	cmd.SetArgs(args)
	cmd.SetIn(a.input)
	cmd.SetOut(a.output)
	cmd.SetErr(a.errors)
	return cmd.ExecuteContext(ctx)
}

func (a *App) rootCommand(ctx context.Context) *cobra.Command {
	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "CLI client for GophKeeper encrypted vaults",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.AddCommand(
		a.registerCommand(ctx),
		a.loginCommand(ctx),
		a.addCommand(ctx),
		a.listCommand(ctx),
		a.getCommand(ctx),
		a.editCommand(ctx),
		a.deleteCommand(ctx),
		a.otpCommand(ctx),
		a.refreshCommand(ctx),
		a.logoutCommand(ctx),
		a.versionCommand(),
	)
	return root
}

func (a *App) registerCommand(ctx context.Context) *cobra.Command {
	var server, username string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new account",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.register(ctx, server, username)
		},
	}
	cmd.Flags().StringVar(&server, "server", "http://localhost:8080", "server URL")
	cmd.Flags().StringVar(&username, "user", "", "username")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func (a *App) loginCommand(ctx context.Context) *cobra.Command {
	var server, username, device string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Create a local session",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.login(ctx, server, username, device)
		},
	}
	cmd.Flags().StringVar(&server, "server", "http://localhost:8080", "server URL")
	cmd.Flags().StringVar(&username, "user", "", "username")
	cmd.Flags().StringVar(&device, "device", "", "device description")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func (a *App) addCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an encrypted secret",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		a.addSecretCommand(ctx, vaultcrypto.KindLogin),
		a.addSecretCommand(ctx, vaultcrypto.KindText),
		a.addSecretCommand(ctx, vaultcrypto.KindCard),
		a.addSecretCommand(ctx, vaultcrypto.KindBinary),
		a.addSecretCommand(ctx, vaultcrypto.KindOTP),
	)
	return cmd
}

func (a *App) addSecretCommand(ctx context.Context, kind vaultcrypto.Kind) *cobra.Command {
	options := addOptions{kind: kind}
	cmd := &cobra.Command{
		Use:   string(kind),
		Short: fmt.Sprintf("Add a %s secret", kind),
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.add(ctx, options)
		},
	}
	cmd.Flags().StringVar(&options.name, "name", "", "display name")
	cmd.Flags().StringVar(&options.metadata, "meta", "", "text metadata")
	switch kind {
	case vaultcrypto.KindBinary:
		cmd.Flags().StringVar(&options.file, "file", "", "file to encrypt")
		_ = cmd.MarkFlagRequired("file")
	case vaultcrypto.KindOTP:
		cmd.Flags().StringVar(&options.uri, "uri", "", "otpauth URI (prefer prompted input)")
	}
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func (a *App) listCommand(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"sync"},
		Short:   "List synchronized secrets",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.list(ctx)
		},
	}
}

func (a *App) getCommand(ctx context.Context) *cobra.Command {
	var outputFile string
	cmd := &cobra.Command{
		Use:   "get [--out PATH] ITEM_ID",
		Short: "Decrypt and show a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.get(ctx, args[0], outputFile)
		},
	}
	cmd.Flags().StringVar(&outputFile, "out", "", "destination for binary record")
	return cmd
}

func (a *App) editCommand(ctx context.Context) *cobra.Command {
	var name, metadata string
	cmd := &cobra.Command{
		Use:   "edit --name NAME [--meta TEXT] ITEM_ID",
		Short: "Update secret metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.edit(ctx, args[0], name, metadata)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new display name")
	cmd.Flags().StringVar(&metadata, "meta", "", "new text metadata")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func (a *App) deleteCommand(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:   "delete ITEM_ID",
		Short: "Delete a synchronized secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.delete(ctx, args[0])
		},
	}
}

func (a *App) otpCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "otp",
		Short: "Work with OTP secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "code ITEM_ID",
		Short: "Generate a TOTP code",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.otpCode(ctx, args[0])
		},
	})
	return cmd
}

func (a *App) refreshCommand(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh the local session",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.refresh(ctx)
		},
	}
}

func (a *App) logoutCommand(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke and remove the local session",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return a.logout(ctx)
		},
	}
}

func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Fprintln(a.output, buildinfo.String())
			return nil
		},
	}
}

func (a *App) register(ctx context.Context, server, username string) error {
	if username == "" {
		return errors.New("register requires --user")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	password, err := a.confirmedPassword()
	if err != nil {
		return err
	}
	setup, err := vaultcrypto.NewVaultSetup(username, password, vaultcrypto.DefaultKDFParameters())
	if err != nil {
		return err
	}
	client, err := a.newRemote(server)
	if err != nil {
		return err
	}
	err = client.Register(ctx, protocol.RegisterRequest{
		Username:        username,
		AuthSalt:        setup.AuthSalt,
		KDF:             setup.KDF,
		AuthKey:         setup.AuthKey,
		WrappedVaultKey: setup.WrappedVaultKey,
		WrapNonce:       setup.WrapNonce,
	})
	if err == nil {
		fmt.Fprintln(a.output, "Account registered. Run login to create a local session.")
	}
	return err
}

func (a *App) login(ctx context.Context, server, username, device string) error {
	if username == "" {
		return errors.New("login requires --user")
	}
	username = strings.ToLower(strings.TrimSpace(username))
	client, err := a.newRemote(server)
	if err != nil {
		return err
	}
	parameters, err := client.LoginParameters(ctx, username)
	if err != nil {
		return err
	}
	password, err := a.password("Master password: ")
	if err != nil {
		return err
	}
	authKey, wrapKey, err := vaultcrypto.DeriveKeys(password, parameters.AuthSalt, parameters.KDF)
	if err != nil {
		return err
	}
	response, err := client.Login(ctx, protocol.LoginRequest{Username: username, AuthKey: authKey, DeviceName: device})
	if err != nil {
		return err
	}
	if _, err := vaultcrypto.UnwrapVaultKey(response.WrappedVaultKey, response.WrapNonce, wrapKey, response.Username); err != nil {
		return err
	}
	sessionPath, err := a.sessionFile()
	if err != nil {
		return err
	}
	if err := session.Save(sessionPath, session.Profile{Server: server, LoginResponse: response}); err != nil {
		return err
	}
	fmt.Fprintln(a.output, "Login successful.")
	return nil
}

func (a *App) refresh(ctx context.Context) error {
	profile, client, err := a.profile()
	if err != nil {
		return err
	}
	tokens, err := client.Refresh(ctx, profile.RefreshToken)
	if err != nil {
		return err
	}
	profile.TokenPair = tokens
	sessionPath, err := a.sessionFile()
	if err != nil {
		return err
	}
	if err := session.Save(sessionPath, profile); err != nil {
		return err
	}
	fmt.Fprintln(a.output, "Session refreshed.")
	return nil
}

func (a *App) logout(ctx context.Context) error {
	profile, client, err := a.profile()
	if err != nil {
		return err
	}
	if err := client.Logout(ctx, profile.AccessToken); err != nil {
		return err
	}
	sessionPath, err := a.sessionFile()
	if err != nil {
		return err
	}
	if err := session.Delete(sessionPath); err != nil {
		return err
	}
	fmt.Fprintln(a.output, "Logged out.")
	return nil
}

func (a *App) add(ctx context.Context, options addOptions) error {
	if options.name == "" {
		return errors.New("add requires --name")
	}
	id, err := vaultcrypto.NewID()
	if err != nil {
		return err
	}
	secret := vaultcrypto.Secret{ID: id, Kind: options.kind, Name: options.name, Metadata: options.metadata}
	switch options.kind {
	case vaultcrypto.KindLogin:
		username, err := a.line("Username: ")
		if err != nil {
			return err
		}
		password, err := a.password("Password: ")
		if err != nil {
			return err
		}
		secret.Login = &vaultcrypto.LoginSecret{Username: username, Password: password}
	case vaultcrypto.KindText:
		value, err := a.password("Sensitive text: ")
		if err != nil {
			return err
		}
		secret.Text = &vaultcrypto.TextSecret{Value: value}
	case vaultcrypto.KindCard:
		holder, err := a.line("Card holder: ")
		if err != nil {
			return err
		}
		number, err := a.password("Card number: ")
		if err != nil {
			return err
		}
		expiry, err := a.line("Expiry: ")
		if err != nil {
			return err
		}
		cvv, err := a.password("CVV: ")
		if err != nil {
			return err
		}
		secret.Card = &vaultcrypto.CardSecret{Number: number, Holder: holder, Expiry: expiry, CVV: cvv}
	case vaultcrypto.KindBinary:
		if options.file == "" {
			return errors.New("binary records require --file")
		}
		data, err := os.ReadFile(options.file)
		if err != nil {
			return err
		}
		secret.Binary = &vaultcrypto.BinarySecret{Filename: filepath.Base(options.file), MIMEType: mime.TypeByExtension(filepath.Ext(options.file)), Data: data}
	case vaultcrypto.KindOTP:
		raw := options.uri
		if raw == "" {
			raw, err = a.password("otpauth URI: ")
			if err != nil {
				return err
			}
		}
		config, err := otp.ParseURI(raw)
		if err != nil {
			return err
		}
		secret.OTP = &config
	default:
		return fmt.Errorf("unsupported secret type %q", options.kind)
	}
	profile, client, vaultKey, err := a.unlocked()
	if err != nil {
		return err
	}
	encrypted, err := vaultcrypto.EncryptSecret(vaultKey, secret)
	if err != nil {
		return err
	}
	item, err := client.PutItem(ctx, profile.AccessToken, encrypted, 0)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Stored %s secret %s (version %d).\n", options.kind, item.ID, item.Version)
	return nil
}

func (a *App) list(ctx context.Context) error {
	profile, client, vaultKey, err := a.unlocked()
	if err != nil {
		return err
	}
	response, err := client.Sync(ctx, profile.AccessToken, 0)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.output, "ID\tTYPE\tNAME\tMETADATA")
	for _, item := range response.Items {
		if item.Deleted {
			continue
		}
		secret, err := vaultcrypto.DecryptSecret(vaultKey, item)
		if err != nil {
			return fmt.Errorf("decrypt item %s: %w", item.ID, err)
		}
		fmt.Fprintf(a.output, "%s\t%s\t%s\t%s\n", secret.ID, secret.Kind, secret.Name, secret.Metadata)
	}
	return nil
}

func (a *App) get(ctx context.Context, itemID, outputFile string) error {
	profile, client, vaultKey, err := a.unlocked()
	if err != nil {
		return err
	}
	item, err := client.GetItem(ctx, profile.AccessToken, itemID)
	if err != nil {
		return err
	}
	secret, err := vaultcrypto.DecryptSecret(vaultKey, item)
	if err != nil {
		return err
	}
	return a.printSecret(secret, outputFile)
}

func (a *App) edit(ctx context.Context, itemID, name, metadata string) error {
	if name == "" {
		return errors.New("edit requires --name")
	}
	profile, client, vaultKey, err := a.unlocked()
	if err != nil {
		return err
	}
	current, err := client.GetItem(ctx, profile.AccessToken, itemID)
	if err != nil {
		return err
	}
	secret, err := vaultcrypto.DecryptSecret(vaultKey, current)
	if err != nil {
		return err
	}
	secret.Name, secret.Metadata = name, metadata
	encrypted, err := vaultcrypto.EncryptSecret(vaultKey, secret)
	if err != nil {
		return err
	}
	updated, err := client.PutItem(ctx, profile.AccessToken, encrypted, current.Version)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Updated %s to version %d.\n", updated.ID, updated.Version)
	return nil
}

func (a *App) delete(ctx context.Context, itemID string) error {
	profile, client, _, err := a.unlocked()
	if err != nil {
		return err
	}
	current, err := client.GetItem(ctx, profile.AccessToken, itemID)
	if err != nil {
		return err
	}
	if _, err := client.DeleteItem(ctx, profile.AccessToken, itemID, current.Version); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Deleted %s.\n", itemID)
	return nil
}

func (a *App) otpCode(ctx context.Context, itemID string) error {
	profile, client, vaultKey, err := a.unlocked()
	if err != nil {
		return err
	}
	item, err := client.GetItem(ctx, profile.AccessToken, itemID)
	if err != nil {
		return err
	}
	secret, err := vaultcrypto.DecryptSecret(vaultKey, item)
	if err != nil {
		return err
	}
	if secret.Kind != vaultcrypto.KindOTP || secret.OTP == nil {
		return errors.New("requested item is not an OTP secret")
	}
	code, err := otp.Generate(*secret.OTP, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintln(a.output, code)
	return nil
}

func (a *App) unlocked() (session.Profile, remote, []byte, error) {
	profile, client, err := a.profile()
	if err != nil {
		return session.Profile{}, nil, nil, err
	}
	password, err := a.password("Master password: ")
	if err != nil {
		return session.Profile{}, nil, nil, err
	}
	_, wrapKey, err := vaultcrypto.DeriveKeys(password, profile.AuthSalt, profile.KDF)
	if err != nil {
		return session.Profile{}, nil, nil, err
	}
	key, err := vaultcrypto.UnwrapVaultKey(profile.WrappedVaultKey, profile.WrapNonce, wrapKey, profile.Username)
	if err != nil {
		return session.Profile{}, nil, nil, err
	}
	return profile, client, key, nil
}

func (a *App) profile() (session.Profile, remote, error) {
	sessionPath, err := a.sessionFile()
	if err != nil {
		return session.Profile{}, nil, err
	}
	profile, err := session.Load(sessionPath)
	if err != nil {
		return session.Profile{}, nil, err
	}
	client, err := a.newRemote(profile.Server)
	return profile, client, err
}

func (a *App) sessionFile() (string, error) {
	if a.sessionPath != "" {
		return a.sessionPath, nil
	}
	path, err := session.DefaultPath()
	if err != nil {
		return "", err
	}
	a.sessionPath = path
	return path, nil
}

func (a *App) printSecret(secret vaultcrypto.Secret, outputFile string) error {
	fmt.Fprintf(a.output, "Name: %s\nType: %s\nMetadata: %s\n", secret.Name, secret.Kind, secret.Metadata)
	switch secret.Kind {
	case vaultcrypto.KindLogin:
		fmt.Fprintf(a.output, "Username: %s\nPassword: %s\n", secret.Login.Username, secret.Login.Password)
	case vaultcrypto.KindText:
		fmt.Fprintln(a.output, secret.Text.Value)
	case vaultcrypto.KindCard:
		fmt.Fprintf(a.output, "Holder: %s\nNumber: %s\nExpiry: %s\nCVV: %s\n", secret.Card.Holder, secret.Card.Number, secret.Card.Expiry, secret.Card.CVV)
	case vaultcrypto.KindBinary:
		if outputFile == "" {
			fmt.Fprintf(a.output, "File: %s (%d bytes). Use get --out PATH %s to write its content.\n", secret.Binary.Filename, len(secret.Binary.Data), secret.ID)
			return nil
		}
		if err := os.WriteFile(outputFile, secret.Binary.Data, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Written to %s.\n", outputFile)
	case vaultcrypto.KindOTP:
		fmt.Fprintf(a.output, "Issuer: %s\nAccount: %s\n", secret.OTP.Issuer, secret.OTP.Account)
	}
	return nil
}

func (a *App) confirmedPassword() (string, error) {
	first, err := a.password("Master password: ")
	if err != nil {
		return "", err
	}
	if len(first) < 10 {
		return "", errors.New("master password must contain at least 10 characters")
	}
	second, err := a.password("Confirm master password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("master passwords do not match")
	}
	return first, nil
}

func (a *App) line(prompt string) (string, error) {
	fmt.Fprint(a.output, prompt)
	value, err := a.input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
