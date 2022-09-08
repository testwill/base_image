package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	flag2 "github.com/aquasecurity/trivy/pkg/flag"
)

func main() {
	var (
		imgName string
	)
	flag.StringVar(&imgName, "image", "", "镜像名")
	flag.Parse()
	fmt.Println(imgName)
	ctx := context.Background()
	cliOpt := flag2.Options{}
	cliOpt.Target = imgName
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
	if report.Metadata.OS == nil {
		fmt.Println("Do not has base image info: ", imgName)
		return
	}
	fmt.Println("os :", report.Metadata.OS.Family)
}

