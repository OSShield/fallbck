package db

import "testing"

func TestJobAllowedOnAgent(t *testing.T) {
	cases := []struct {
		job, agent string
		want       bool
	}{
		{"filesystem", "filesystem", true},
		{"", "", true},
		{"database", "database", true},
		{"kubernetes", "kubernetes", true},
		{"database", "kubernetes", true},
		{"kubernetes", "database", false},
		{"filesystem", "kubernetes", false},
		{"database", "filesystem", true}, // the combined agent, gated by Agent.DBTools
		{"docker", "filesystem", true},
		{"docker", "database", false},
	}
	for _, c := range cases {
		if got := JobAllowedOnAgent(c.job, c.agent); got != c.want {
			t.Errorf("JobAllowedOnAgent(%q, %q) = %v, want %v", c.job, c.agent, got, c.want)
		}
	}
}

func TestNormalizeJobTypeAndPVEPairing(t *testing.T) {
	if jt, ok := NormalizeJobType("pve"); !ok || jt != JobTypePVE {
		t.Errorf("pve job type: %q %v", jt, ok)
	}
	if jt, ok := NormalizeJobType(""); !ok || jt != JobTypeFilesystem {
		t.Errorf("empty job type: %q %v", jt, ok)
	}
	if _, ok := NormalizeAgentType("pve"); ok {
		t.Error("pve must not be an agent type")
	}
	if !JobAllowedOnAgent("pve", "filesystem") || JobAllowedOnAgent("pve", "database") || JobAllowedOnAgent("pve", "kubernetes") {
		t.Error("pve jobs run on filesystem agents only")
	}
}

func TestAgentCanRunJob(t *testing.T) {
	fs := &Agent{AgentType: AgentTypeFilesystem}
	if fs.CanRunJob("database") || fs.CanRunJob("pve") || fs.CanRunJob("docker") || !fs.CanRunJob("filesystem") {
		t.Error("filesystem agent without capabilities")
	}
	fs.DBTools, fs.PVEHost, fs.DockerHost = true, true, true
	if !fs.CanRunJob("database") || !fs.CanRunJob("pve") || !fs.CanRunJob("docker") || fs.CanRunJob("kubernetes") {
		t.Error("filesystem agent with capabilities")
	}
	dbAgent := &Agent{AgentType: AgentTypeDatabase}
	if !dbAgent.CanRunJob("database") || dbAgent.CanRunJob("filesystem") {
		t.Error("database agent")
	}
}

func TestAgentCanRunDBEngine(t *testing.T) {
	modern := &Agent{AgentType: AgentTypeFilesystem, DBTools: true, DBEngines: []string{"postgres", "mssql"}}
	if !modern.CanRunDBEngine("postgres") || !modern.CanRunDBEngine("mssql") || modern.CanRunDBEngine("mysql") {
		t.Error("an agent with an engine list goes by the list")
	}
	windows := &Agent{AgentType: AgentTypeFilesystem, DBTools: true, DBEngines: []string{"mssql"}}
	if !windows.CanRunDBEngine("mssql") || windows.CanRunDBEngine("postgres") {
		t.Error("a host without client tools still offers mssql, and only mssql")
	}
	legacy := &Agent{AgentType: AgentTypeFilesystem, DBTools: true}
	if !legacy.CanRunDBEngine("postgres") || legacy.CanRunDBEngine("mssql") {
		t.Error("an agent that only sent db_tools predates mssql")
	}
	if (&Agent{AgentType: AgentTypeFilesystem}).CanRunDBEngine("postgres") {
		t.Error("no capability reported")
	}
	for _, typ := range []string{AgentTypeKubernetes, AgentTypeDatabase} {
		a := &Agent{AgentType: typ}
		if !a.CanRunDBEngine("mysql") || a.CanRunDBEngine("mssql") {
			t.Errorf("%s agents run everything but SQL Server", typ)
		}
	}
	if got := CleanDBEngines([]string{"PostgreSQL", "mssql", "mssql", "oracle"}); len(got) != 2 || got[0] != "postgres" || got[1] != "mssql" {
		t.Errorf("CleanDBEngines: %v", got)
	}
}
