package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegration_StartApplication(t *testing.T) {
	app, dbCtr := Setup(t)

	assert.NotNil(t, dbCtr)
	assert.NotNil(t, app)

	Cleanup(t, dbCtr)
}
