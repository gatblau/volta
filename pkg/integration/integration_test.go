// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package integration

import (
	"testing"

	"github.com/cucumber/godog"
	"github.com/gatblau/volta/pkg/integration/step_definitions"
)

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		Name:                 "integration",
		TestSuiteInitializer: step_definitions.InitializeTestSuite,
		ScenarioInitializer:  step_definitions.InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("integration tests failed")
	}
}
