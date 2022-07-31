package main

import (
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func main() {
	var model, token string

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "model",
				Usage:       "Operating mode; r:replace, b:backup",
				DefaultText: "b",
				Aliases:     []string{"m"},
				Required:    true,
				Destination: &model,
			},
			&cli.StringFlag{
				Name:    "download-path",
				Usage:   "The path where the image is stored",
				Aliases: []string{"dp"},

				Required: false,
			},
			&cli.StringFlag{
				Name:    "markdown-path",
				Usage:   "The path where the markdown file is stored",
				Aliases: []string{"mp"},

				Required: false,
			},
			&cli.StringFlag{
				Name:        "token",
				Usage:       "Upload token",
				Aliases:     []string{"tk"},
				Required:    false,
				Destination: &token,
			},
		},
		Action: func(c *cli.Context) error {

			color.Green("Current Model is [%v]", "starting")

			return nil
		},
		Name:  "dt(dev tool)",
		Usage: "dev tool is a tool to simplify the daily use of commands for developers.",
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
