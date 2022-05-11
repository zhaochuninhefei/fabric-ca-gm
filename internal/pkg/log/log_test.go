/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"testing"

	log "gitee.com/zhaochuninhefei/zcgolog/zclog"
	"github.com/stretchr/testify/assert"
)

func TestSetDefaultLogLevel(t *testing.T) {
	SetDefaultLogLevel("warning", false)
	assert.Equal(t, log.LOG_LEVEL_WARNING, log.Level)

	SetDefaultLogLevel("warning", true)
	assert.Equal(t, log.LOG_LEVEL_DEBUG, log.Level)
}

func TestDefaultLogLevel(t *testing.T) {
	err := SetLogLevel("info", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_INFO, log.Level)

	err = SetLogLevel("warning", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_WARNING, log.Level)

	err = SetLogLevel("debug", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_DEBUG, log.Level)

	err = SetLogLevel("error", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_ERROR, log.Level)

	err = SetLogLevel("panic", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_PANIC, log.Level)

	err = SetLogLevel("fatal", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_FATAL, log.Level)

	err = SetLogLevel("badLogLevel", false)
	assert.NoError(t, err)
	assert.Equal(t, log.LOG_LEVEL_INFO, log.Level)

	err = SetLogLevel("warning", true)
	assert.Error(t, err)
}
