package main

import (
	"github.com/hibouhq/hibou/cmd"
	"github.com/hibouhq/hibou/internal/initproc"
)

// @title           hibou API
// @version         1.0
// @description     DevSecOps security platform API
// @host            localhost:8585
// @BasePath        /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Enter your API key with the "Bearer " prefix
func main() {
	// Before anything else: as PID 1 this becomes the reaping supervisor and
	// never returns, so it must not share a process with code that execs.
	initproc.SuperviseIfPID1()
	cmd.Execute()
}
