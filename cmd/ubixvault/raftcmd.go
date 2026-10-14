package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/client"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

const raftUsage = "usage: operator raft list-peers | join | join-token | remove-peer <id> | snapshot save|restore|force-restore <file> | autopilot-state | rotate-ca | recover -data <dir> -peers <file> | export-mysql <file> | digest <file>"

func operatorRaft(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("%s", raftUsage)
	}
	switch args[0] {
	case "list-peers":
		return operatorRaftListPeers(args[1:])
	case "join":
		return operatorRaftJoin(args[1:])
	case "join-token":
		return operatorRaftJoinToken(args[1:])
	case "remove-peer":
		return operatorRaftRemovePeer(args[1:])
	case "snapshot":
		return operatorRaftSnapshot(args[1:])
	case "autopilot-state":
		return operatorRaftAutopilot(args[1:])
	case "rotate-ca":
		return operatorRaftRotateCA(args[1:])
	case "recover":
		return operatorRaftRecover(args[1:])
	case "export-mysql":
		return operatorRaftExportMySQL(args[1:])
	case "digest":
		return operatorRaftDigest(args[1:])
	default:
		return fmt.Errorf("unknown raft subcommand %q\n%s", args[0], raftUsage)
	}
}

func operatorRaftListPeers(args []string) error {
	fs := flag.NewFlagSet("operator raft list-peers", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	cfg, err := c.RaftConfiguration(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("%-24s %-32s %-10s %s\n", "Node", "Address", "State", "Voter")
	for _, s := range cfg.Config.Servers {
		state := "follower"
		if s.Leader {
			state = "leader"
		}
		fmt.Printf("%-24s %-32s %-10s %t\n", s.NodeID, s.Address, state, s.Voter)
	}
	return nil
}

// operatorRaftJoin asks the node at -address (a fresh, sealed one) to join the
// cluster at the leader address given as the argument.
func operatorRaftJoin(args []string) error {
	fs := flag.NewFlagSet("operator raft join", flag.ExitOnError)
	cc := registerClientFlags(fs, false)
	tokenFile := fs.String("token-file", "", "file holding the join token (default: $UBIXVAULT_RAFT_JOIN_TOKEN)")
	leaderCA := fs.String("leader-ca-cert", "", "PEM file with the CA that signed the leader's API certificate (default: the node's system roots)")
	retry := fs.Bool("retry", false, "keep retrying in the background instead of failing on the first error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	leader := fs.Arg(0)
	if leader == "" {
		return fmt.Errorf("usage: operator raft join [-address <this node>] [-token-file F] [-leader-ca-cert F] [-retry] <leader API address>")
	}
	tok, err := tokenSource(*tokenFile)()
	if err != nil {
		return err
	}
	req := client.RaftJoinRequest{LeaderAPIAddr: leader, JoinToken: tok, Retry: *retry}
	if *leaderCA != "" {
		b, err := os.ReadFile(*leaderCA) //nolint:gosec // G304: operator-provided path
		if err != nil {
			return fmt.Errorf("read -leader-ca-cert: %w", err)
		}
		req.LeaderCACert = string(b)
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	res, err := c.RaftJoin(context.Background(), req)
	if err != nil {
		return err
	}
	if res.Joined {
		fmt.Println("Joined. The node replicates as a non-voter and is promoted once caught up; unseal it as usual.")
	} else {
		fmt.Println("Joining in the background; watch the node's log, or `operator raft list-peers` on the leader.")
	}
	return nil
}

func operatorRaftJoinToken(args []string) error {
	fs := flag.NewFlagSet("operator raft join-token", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	ttl := fs.Duration("ttl", 0, "token lifetime (default 15m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	tok, exp, err := c.RaftJoinToken(context.Background(), *ttl)
	if err != nil {
		return err
	}
	fmt.Printf("Join token: %s\n", tok)
	fmt.Printf("Single use; expires %s.\n", exp.Local().Format(time.RFC3339))
	return nil
}

func operatorRaftRemovePeer(args []string) error {
	fs := flag.NewFlagSet("operator raft remove-peer", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return fmt.Errorf("usage: operator raft remove-peer <node id>")
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	if err := c.RaftRemovePeer(context.Background(), id); err != nil {
		return err
	}
	fmt.Printf("Removed %s from the cluster.\n", id)
	return nil
}

func operatorRaftSnapshot(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: operator raft snapshot save|restore|force-restore <file>")
	}
	switch args[0] {
	case "save":
		return operatorRaftSnapshotSave(args[1:])
	case "restore":
		return operatorRaftSnapshotRestore(args[1:], false)
	case "force-restore":
		return operatorRaftSnapshotRestore(args[1:], true)
	default:
		return fmt.Errorf("unknown raft snapshot subcommand %q", args[0])
	}
}

func operatorRaftSnapshotSave(args []string) error {
	fs := flag.NewFlagSet("operator raft snapshot save", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := fs.Arg(0)
	if path == "" {
		return fmt.Errorf("usage: operator raft snapshot save <file>")
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-provided output path
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	if err := c.RaftSnapshotSave(context.Background(), f); err != nil {
		_ = f.Close()
		_ = os.Remove(path) // never leave a partial backup that looks like one
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("snapshot written to %s\n", path)
	return nil
}

func operatorRaftSnapshotRestore(args []string, force bool) error {
	name := "restore"
	if force {
		name = "force-restore"
	}
	fs := flag.NewFlagSet("operator raft snapshot "+name, flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := fs.Arg(0)
	if path == "" {
		return fmt.Errorf("usage: operator raft snapshot %s <file>", name)
	}
	f, err := os.Open(path) //nolint:gosec // G304: operator-provided snapshot path
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	if err := c.RaftSnapshotRestore(context.Background(), f, force); err != nil {
		return err
	}
	fmt.Println("Snapshot restored; the cluster's data was replaced and membership kept.")
	if force {
		fmt.Println("The restored store's own unseal keys now apply: re-seal and unseal every replica with them.")
	}
	return nil
}

func operatorRaftAutopilot(args []string) error {
	fs := flag.NewFlagSet("operator raft autopilot-state", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	st, err := c.RaftAutopilotState(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("Healthy:           %t\nFailure tolerance: %d\nLeader:            %s\n\n", st.Healthy, st.FailureTolerance, st.Leader)
	ids := make([]string, 0, len(st.Servers))
	for id := range st.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Printf("%-24s %-32s %-10s %s\n", "Node", "Address", "Status", "Healthy")
	for _, id := range ids {
		s := st.Servers[id]
		fmt.Printf("%-24s %-32s %-10s %t\n", id, s.Address, s.Status, s.Healthy)
	}
	return nil
}

// operatorRaftRecover stages a peers.json on a stopped node (quorum-loss
// recovery); the server applies and deletes it on its next start.
func operatorRaftRecover(args []string) error {
	fs := flag.NewFlagSet("operator raft recover", flag.ExitOnError)
	raft := raftFlags(fs)
	dataDir := fs.String("data", "", "the stopped node's data directory (required)")
	peers := fs.String("peers", "", "JSON file listing the surviving cluster: [{\"id\":\"n1\",\"address\":\"host:port\"}] (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *peers == "" {
		return fmt.Errorf("usage: operator raft recover -data <dir> -peers <file> [-raft-node-id <id>]")
	}
	return recoverRaft(raft, *dataDir, *peers)
}

func recoverRaft(r *raftOpts, dataDir, peersPath string) error {
	blob, err := os.ReadFile(peersPath) //nolint:gosec // G304: operator-provided peers file
	if err != nil {
		return fmt.Errorf("read %q: %w", peersPath, err)
	}
	servers, err := raftstore.ParsePeers(blob)
	if err != nil {
		return err
	}
	nodeID, _, err := r.resolve("https://host:0") // only the node ID matters here
	if err != nil {
		return err
	}
	if err := raftstore.WriteRecovery(dataDir, nodeID, servers); err != nil {
		return err
	}
	fmt.Printf("Recovery staged for node %s with %d peer(s).\n", nodeID, len(servers))
	fmt.Println("WARNING: writes acknowledged only by members missing from the list can be lost.")
	fmt.Println("Start this node with -storage raft; it applies the list once and deletes the file.")
	fmt.Println("Wipe the data directory of every other node and re-join them with a join token.")
	return nil
}

func operatorRaftRotateCA(args []string) error {
	fs := flag.NewFlagSet("operator raft rotate-ca", flag.ExitOnError)
	cc := registerClientFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := cc.newClient()
	if err != nil {
		return err
	}
	if err := c.RaftRotateCA(context.Background()); err != nil {
		return err
	}
	fmt.Println("The cluster CA was replaced on this node (the leader).")
	fmt.Println("Nodes keep trusting the old CA until restarted, so quorum may be lost meanwhile.")
	fmt.Println("Now re-seal or restart every node (followers first, the leader last) and unseal them.")
	fmt.Println("A node that missed the new CA must be removed, wiped and re-joined (operator raft remove-peer / join-token).")
	fmt.Println("See docs/design/raft-storage.md, \"Cluster CA rotation\".")
	return nil
}
