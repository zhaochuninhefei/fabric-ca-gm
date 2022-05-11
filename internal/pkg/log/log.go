/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"strings"

	log "gitee.com/zhaochuninhefei/zcgolog/zclog"
	"github.com/pkg/errors"
)

// Constants defined for the different log levels
const (
	DEBUG   = "debug"
	INFO    = "info"
	WARNING = "warning"
	ERROR   = "error"
	PANIC   = "panic"
	FATAL   = "fatal"
)

// SetDefaultLogLevel sets the default log level
func SetDefaultLogLevel(logLevel string, debug bool) {
	log.Debug("Set default log level: ", logLevel)
	setLogLevel(logLevel, debug, true)
}

// SetLogLevel sets the log level
func SetLogLevel(logLevel string, debug bool) error {
	log.Debug("Set log level: ", logLevel)
	return setLogLevel(logLevel, debug, false)
}

func setLogLevel(logLevel string, debug, override bool) error {
	if debug {
		if logLevel != "" && !override {
			return errors.Errorf("Can't specify log level '%s' and set debug to true at the same time", logLevel)
		} else if override {
			logLevel = "debug"
		} else if logLevel == "" {
			logLevel = "debug"
		}
	}

	switch strings.ToLower(logLevel) {
	case INFO:
		log.Level = log.LOG_LEVEL_INFO
	case WARNING:
		log.Level = log.LOG_LEVEL_WARNING
	case DEBUG:
		log.Level = log.LOG_LEVEL_DEBUG
	case ERROR:
		log.Level = log.LOG_LEVEL_ERROR
	case PANIC:
		log.Level = log.LOG_LEVEL_PANIC
	case FATAL:
		log.Level = log.LOG_LEVEL_FATAL
	default:
		log.Debug("Unrecognized log level, defaulting to 'info'")
		log.Level = log.LOG_LEVEL_INFO
	}

	return nil
}
