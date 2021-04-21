package utils

import (
	"os"

	"github.com/sirupsen/logrus"
)

func GetLogger() *logrus.Logger {
	return &logrus.Logger{

		Out: os.Stderr,

		Formatter: new(logrus.TextFormatter),

		Hooks: make(logrus.LevelHooks),

		Level: logrus.DebugLevel,
	}
}
