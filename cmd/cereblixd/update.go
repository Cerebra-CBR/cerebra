package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cereblix/core"
	"cereblix/node"
)

// nodeVersion is this binary's software release version. The auto-updater
// installs a newer one named in the authority-signed manifest; the consensus
// version it signals in blocks is core.NodeConsensusVersion (separate).
const nodeVersion = "2.0.8"

// Where to look for the signed upgrade manifest, in order. Every source is
// verified against core.AuthorityPubKey, so an untrusted mirror cannot harm us;
// the extra sources exist only so a node still updates where GitHub is blocked
// (RU/CIS): our Cloudflare origin and the RU relay are reachable there.
var manifestURLs = []string{
	"https://github.com/Cerebra-CBR/cereblix/releases/latest/download/upgrade.json",
	"https://cereblix.com/upgrade.json",
	"https://cereblix.com/api/upgrade",
	"https://ru.cereblix.com/upgrade.json",
	"https://ru.cereblix.com/api/upgrade",
}

func nodePlatform() string { return runtime.GOOS + "-" + runtime.GOARCH } // e.g. linux-amd64

// verNewer reports whether version a > b ("2.10.0" > "2.9.0").
func verNewer(a, b string) bool {
	ap, bp := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	for i := 0; i < len(ap); i++ {
		var x, y int
		fmt.Sscanf(ap[i], "%d", &x)
		if i < len(bp) {
			fmt.Sscanf(bp[i], "%d", &y)
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// shouldInstall reports whether to auto-install manifestVer, given the version
// we run and any version blocked (rolled back / blacklisted). We install only
// something strictly newer than both - so a bad release is never re-downloaded
// in a loop, yet the eventual fix (a higher version) installs automatically.
// Pure, unit-tested.
func shouldInstall(manifestVer, nodeVer, blockedVer string) bool {
	if !verNewer(manifestVer, nodeVer) {
		return false
	}
	if blockedVer != "" && !verNewer(manifestVer, blockedVer) {
		return false
	}
	return true
}

// manifestSources returns the URLs to try, allowing an env override (comma-
// separated, tried first) for testnets / private mirrors.
func manifestSources() []string {
	if v := strings.TrimSpace(os.Getenv("CEREBLIX_MANIFEST_URL")); v != "" {
		var extra []string
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				extra = append(extra, u)
			}
		}
		return append(extra, manifestURLs...)
	}
	return manifestURLs
}

// fetchManifest returns the first authority-verified manifest among the sources.
func fetchManifest() (core.UpgradeManifest, bool) {
	cl := &http.Client{Timeout: 8 * time.Second}
	for _, u := range manifestSources() {
		resp, err := cl.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var m core.UpgradeManifest
		if json.Unmarshal(body, &m) != nil {
			continue
		}
		if !m.Verify() { // reject anything not signed by the authority key
			log.Printf("auto-update: ignoring manifest from %s (bad/absent authority signature)", u)
			continue
		}
		return m, true
	}
	return core.UpgradeManifest{}, false
}

// selfUpdateNode downloads the binary named in the (already authority-verified)
// manifest, checks its sha256, and atomically swaps it in, keeping a .old backup.
func selfUpdateNode(bin core.UpgradeBinary) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	mirrors := bin.URLs
	if len(mirrors) == 0 && bin.URL != "" {
		mirrors = []string{bin.URL} // older single-mirror manifests
	}
	if len(mirrors) == 0 {
		return fmt.Errorf("manifest binary has no download URL")
	}
	var lastErr error
	for _, u := range mirrors {
		data, err := downloadVerified(u, bin.SHA256)
		if err != nil {
			log.Printf("auto-update: mirror failed (%s): %v — trying next", u, err)
			lastErr = err
			continue
		}
		return swapBinary(exe, data)
	}
	return lastErr
}

// downloadVerified fetches a URL and returns its bytes only if they match the
// expected sha256 (and look like a real binary).
func downloadVerified(url, wantSHA string) ([]byte, error) {
	cl := &http.Client{Timeout: 240 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(data) < 1_000_000 {
		return nil, fmt.Errorf("file too small (%d bytes)", len(data))
	}
	if sum := hex.EncodeToString(sha256Sum(data)); !strings.EqualFold(sum, wantSHA) {
		return nil, fmt.Errorf("sha256 mismatch: got %s want %s", sum, wantSHA)
	}
	return data, nil
}

// swapBinary installs new bytes over the running executable, keeping a .old
// backup. Atomic on Unix; rename-aside on Windows (a running .exe can't be
// overwritten there).
func swapBinary(exe string, data []byte) error {
	os.Remove(exe + ".new")
	if err := os.WriteFile(exe+".new", data, 0o755); err != nil {
		return err
	}
	os.Remove(exe + ".old")
	if runtime.GOOS == "windows" {
		if err := os.Rename(exe, exe+".old"); err != nil {
			return err
		}
		if err := os.Rename(exe+".new", exe); err != nil {
			os.Rename(exe+".old", exe) // revert
			return err
		}
	} else {
		if cur, err := os.ReadFile(exe); err == nil {
			if err := os.WriteFile(exe+".old", cur, 0o755); err != nil {
				return fmt.Errorf("backup current binary: %w", err)
			}
		}
		if err := os.Rename(exe+".new", exe); err != nil {
			return err
		}
	}
	return nil
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// restartSelf relaunches the freshly-swapped binary. Under systemd (Restart=
// always) exiting is enough and avoids double instances; otherwise re-exec.
func restartSelf() {
	if os.Getenv("INVOCATION_ID") != "" {
		log.Print("auto-update: exiting for systemd to relaunch the new binary")
		os.Exit(0)
	}
	exe, _ := os.Executable()
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if cmd.Start() == nil {
		os.Exit(0)
	}
}

func ternary(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// applyManifest serves the manifest to peers, warns about pending forks, and (if
// enabled and not paused) auto-updates to a newer, non-blocked version.
func applyManifest(n *node.Node, m core.UpgradeManifest, enabled bool) {
	n.SetUpgrade(m)
	for _, f := range m.Forks {
		if verNewer(f.MinVersion, nodeVersion) {
			log.Printf("‼ NETWORK UPGRADE '%s' needs node >= v%s (you run v%s); activation floor height %d. %s",
				f.Name, f.MinVersion, nodeVersion, f.Height, ternary(enabled, "Auto-update is ON.", "Auto-update is OFF - update manually!"))
		}
	}
	if !enabled {
		return
	}
	if envHalted() {
		log.Printf("auto-update: paused by an unresolved environment problem; not installing v%s. Run `cereblixd -diagnose`.", m.Version)
		return
	}
	blocked := blockedVersion()
	if !shouldInstall(m.Version, nodeVersion, blocked) {
		if blocked != "" && verNewer(m.Version, nodeVersion) && !verNewer(m.Version, blocked) {
			log.Printf("auto-update: NOT installing v%s - v%s (or older) was rolled back as unhealthy; staying on v%s until a NEWER fix is published", m.Version, blocked, nodeVersion)
		}
		return
	}
	bin, ok := m.Binaries[nodePlatform()]
	if !ok {
		log.Printf("auto-update: manifest v%s has no binary for %s; update manually", m.Version, nodePlatform())
		return
	}
	log.Printf("auto-update: v%s available, downloading for %s ...", m.Version, nodePlatform())
	if err := selfUpdateNode(bin); err != nil {
		log.Printf("auto-update FAILED: %v (will retry next check)", err)
		return
	}
	log.Printf("auto-update: installed v%s, restarting", m.Version)
	markPending(m.Version) // arm the self-healing guard for the next boot
	restartSelf()
}

// updateInterval is the gap between manifest checks (override for tests/ops).
func updateInterval() time.Duration {
	if s := os.Getenv("CEREBLIX_UPDATE_INTERVAL_SECS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 20 * time.Minute
}

// autoUpdateLoop checks for a new signed manifest shortly after start, then
// periodically. Safe to run on every node; verification gates everything.
func autoUpdateLoop(n *node.Node, enabled bool) {
	iv := updateInterval()
	init := iv
	if init > 15*time.Second {
		init = 15 * time.Second // settle, but don't wait a whole interval
	}
	time.Sleep(init)
	for {
		if m, ok := fetchManifest(); ok {
			// Re-check the persistent opt-out each tick so `-autoupdate off` takes
			// effect without a restart. The manifest is still served + fork warnings
			// still fire when disabled; only the install is skipped.
			applyManifest(n, m, enabled && !autoUpdateDisabled())
		}
		time.Sleep(iv)
	}
}

// runUpdateOnce implements the -update flag: fetch, install if newer & not
// blocked, then exit.
func runUpdateOnce() {
	m, ok := fetchManifest()
	if !ok {
		fmt.Println("Could not fetch a valid upgrade manifest (GitHub may be blocked; tried origin + relay too).")
		return
	}
	blocked := blockedVersion()
	if !shouldInstall(m.Version, nodeVersion, blocked) {
		if blocked != "" && !verNewer(m.Version, blocked) {
			fmt.Printf("Latest is v%s but it was rolled back as unhealthy earlier; waiting for a newer fix. Staying on v%s.\n", m.Version, nodeVersion)
		} else {
			fmt.Printf("Already up to date (v%s).\n", nodeVersion)
		}
		return
	}
	bin, ok := m.Binaries[nodePlatform()]
	if !ok {
		fmt.Printf("Manifest v%s has no binary for %s.\n", m.Version, nodePlatform())
		return
	}
	fmt.Printf("Updating v%s -> v%s ...\n", nodeVersion, m.Version)
	if err := selfUpdateNode(bin); err != nil {
		fmt.Println("Update failed:", err)
		return
	}
	markPending(m.Version) // arm the rollback guard for the next boot
	fmt.Println("✔ Updated to v" + m.Version + ". Restart cereblixd to run it.")
}
