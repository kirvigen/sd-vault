// Command vault opens an encrypted folder that lives next to the executable
// (for example on an SD card) in the browser, without installing anything.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"sd-vault/internal/vault"
	"sd-vault/internal/web"
)

var version = "dev"

const minPasswordLen = 8

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nОшибка: %v\n", err)
		pauseOnWindows()
		os.Exit(1)
	}
}

func run() error {
	dirFlag := flag.String("dir", "", "папка сейфа (по умолчанию «vault» рядом с программой)")
	noBrowser := flag.Bool("no-browser", false, "не открывать браузер, только напечатать ссылку")
	port := flag.Int("port", 0, "порт на 127.0.0.1 (0 — случайный)")
	showVersion := flag.Bool("version", false, "показать версию")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	dir := *dirFlag
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir = filepath.Join(filepath.Dir(exe), "vault")
	}

	in := newPasswordReader()
	v, err := unlock(dir, in)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		v.Close()
		return err
	}
	host := ln.Addr().String()
	token := randomToken()
	srv := web.New(v, token, host)
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go httpSrv.Serve(ln)

	url := "http://" + host + "/?t=" + token
	fmt.Printf("\nСейф открыт: %s\n", dir)
	fmt.Printf("Адрес (только для этого компьютера):\n  %s\n\n", url)
	fmt.Println("Закрыть сейф: кнопка «Закрыть сейф» в браузере или Ctrl+C здесь.")
	if !*noBrowser {
		if err := openBrowser(url); err != nil {
			fmt.Println("Браузер не открылся сам — скопируйте адрес выше.")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case <-sig:
	case <-srv.Closed():
	}
	signal.Stop(sig)

	fmt.Println("\nЗакрываю сейф…")
	// Let running uploads finish: each one is committed only when it ends.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		httpSrv.Close()
	}
	v.Close()
	fmt.Println("Сейф закрыт, все изменения записаны. Карту можно вынимать.")
	return nil
}

func unlock(dir string, in *passwordReader) (*vault.Vault, error) {
	if !vault.Exists(dir) {
		fmt.Printf("Сейфа ещё нет. Будет создан новый в папке:\n  %s\n\n", dir)
		fmt.Println("Придумайте пароль. Восстановить его нельзя: без пароля файлы не прочитать.")
		for {
			pw, err := in.read("Новый пароль: ")
			if err != nil {
				return nil, err
			}
			if len([]rune(pw)) < minPasswordLen {
				fmt.Printf("Слишком короткий: нужно не меньше %d символов.\n", minPasswordLen)
				continue
			}
			again, err := in.read("Повторите пароль: ")
			if err != nil {
				return nil, err
			}
			if pw != again {
				fmt.Println("Пароли не совпали, ещё раз.")
				continue
			}
			fmt.Println("Создаю сейф…")
			return vault.Create(dir, pw)
		}
	}
	for attempt := 1; ; attempt++ {
		pw, err := in.read("Пароль: ")
		if err != nil {
			return nil, err
		}
		fmt.Println("Проверяю…")
		v, err := vault.Open(dir, pw)
		if errors.Is(err, vault.ErrWrongPassword) && attempt < 5 {
			fmt.Println("Неверный пароль.")
			continue
		}
		return v, err
	}
}

// passwordReader reads from the terminal without echo, or line by line from
// a pipe when stdin is not a terminal (scripts, tests).
type passwordReader struct {
	tty   bool
	lines *bufio.Scanner
}

func newPasswordReader() *passwordReader {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return &passwordReader{tty: true}
	}
	return &passwordReader{lines: bufio.NewScanner(os.Stdin)}
}

func (p *passwordReader) read(prompt string) (string, error) {
	fmt.Print(prompt)
	if p.tty {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		s := string(b)
		clear(b)
		return s, nil
	}
	if !p.lines.Scan() {
		fmt.Println()
		return "", errors.New("пароль не введён")
	}
	fmt.Println()
	return strings.TrimRight(p.lines.Text(), "\r"), nil
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// pauseOnWindows keeps a double-clicked console window open long enough to
// read the error.
func pauseOnWindows() {
	if runtime.GOOS == "windows" && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Нажмите Enter, чтобы закрыть окно.")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
