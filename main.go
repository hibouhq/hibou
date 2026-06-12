package main

import "github.com/hibouhq/hibou/cmd"

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
	cmd.Execute()
}
