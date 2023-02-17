package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	flag2 "github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func main() {
	var (
		srcName string
	)
	flag.StringVar(&srcName, "src", "", "镜像名")
	flag.Parse()
	fmt.Println(srcName)
	ctx := context.Background()
	cliOpt := flag2.Options{}
	cliOpt.ListAllPkgs = true
	dbOpt := flag2.DBOptions{}
	dbOpt.SkipDBUpdate = true
	cliOpt.Target = srcName
	cliOpt.OfflineScan = true
	cliOpt.SecurityChecks = []string{"vuln"}
	cliOpt.DBOptions = dbOpt
	cliOpt.GlobalOptions.CacheDir = utils.DefaultCacheDir()
	cliOpt.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	fmt.Println(cliOpt.GlobalOptions.CacheDir)
	r, err := artifact.NewRunner(ctx, cliOpt)
	if err != nil {
		fmt.Println("artifact.NewRunner err:", err.Error())
		return
	}

	defer r.Close(ctx)
	report, err := r.ScanImage(ctx, cliOpt)
	if err != nil {
		fmt.Println("ScanImage err:", err.Error())
		return
	}
	data, _ := json.Marshal(report)
	fmt.Println(string(data))
}

