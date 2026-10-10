// CVSS v4.0 scoring, ported from FIRST's reference calculator
// (https://github.com/FIRSTdotorg/cvss-v4-calculator, cvss_score.js).
//
// Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// v4.0 has no closed formula: a vector falls into a MacroVector (six
// equivalence levels, EQ1..EQ6) whose score is looked up, then lowered by the
// vector's mean distance from the MacroVector's most severe vectors. The port
// keeps the reference's order of floating-point operations so that every
// score matches FIRST's calculator exactly (testdata/v4-golden.json, scored
// by the reference itself).

package cvss

import (
	"math"
	"strconv"
	"strings"
)

var (
	v4AVLevels = map[string]float64{"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
	v4PRLevels = map[string]float64{"N": 0.0, "L": 0.1, "H": 0.2}
	v4UILevels = map[string]float64{"N": 0.0, "P": 0.1, "A": 0.2}
	v4ACLevels = map[string]float64{"L": 0.0, "H": 0.1}
	v4ATLevels = map[string]float64{"N": 0.0, "P": 0.1}
	v4VCLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4VILevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4VALevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4SCLevels = map[string]float64{"H": 0.1, "L": 0.2, "N": 0.3}
	v4SILevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	v4SALevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	v4CRLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
	v4IRLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
	v4ARLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
)

// v4Metrics is a vector's metrics with the reference's defaulting rules.
type v4Metrics map[string]string

// m returns the effective value of a metric: E, CR, IR and AR default to
// their worst case when not defined (X), and a modified environmental metric
// (MAV, MVC...) overrides its base metric when defined.
func (sel v4Metrics) m(metric string) string {
	selected := sel[metric]
	if selected == "" {
		selected = "X"
	}
	switch {
	case metric == "E" && selected == "X":
		return "A"
	case (metric == "CR" || metric == "IR" || metric == "AR") && selected == "X":
		return "H"
	}
	if modified, ok := sel["M"+metric]; ok && modified != "X" && modified != "" {
		return modified
	}
	return selected
}

func (sel v4Metrics) macroVector() string {
	var eq1, eq2, eq3, eq4, eq5, eq6 int
	av, pr, ui := sel.m("AV"), sel.m("PR"), sel.m("UI")
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq1 = 0
	case (av == "N" || pr == "N" || ui == "N") && av != "P":
		eq1 = 1
	default:
		eq1 = 2
	}
	if sel.m("AC") != "L" || sel.m("AT") != "N" {
		eq2 = 1
	}
	vc, vi, va := sel.m("VC"), sel.m("VI"), sel.m("VA")
	switch {
	case vc == "H" && vi == "H":
		eq3 = 0
	case vc == "H" || vi == "H" || va == "H":
		eq3 = 1
	default:
		eq3 = 2
	}
	switch {
	case sel.m("MSI") == "S" || sel.m("MSA") == "S":
		eq4 = 0
	case sel.m("SC") == "H" || sel.m("SI") == "H" || sel.m("SA") == "H":
		eq4 = 1
	default:
		eq4 = 2
	}
	switch sel.m("E") {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	case "U":
		eq5 = 2
	}
	eq6 = 1
	if (sel.m("CR") == "H" && vc == "H") || (sel.m("IR") == "H" && vi == "H") || (sel.m("AR") == "H" && va == "H") {
		eq6 = 0
	}
	return strconv.Itoa(eq1) + strconv.Itoa(eq2) + strconv.Itoa(eq3) + strconv.Itoa(eq4) + strconv.Itoa(eq5) + strconv.Itoa(eq6)
}

func v4LookupScore(macro string) float64 {
	if score, ok := v4Lookup[macro]; ok {
		return score
	}
	return math.NaN()
}

func macroOf(levels ...int) string {
	var b strings.Builder
	for _, level := range levels {
		b.WriteString(strconv.Itoa(level))
	}
	return b.String()
}

func parseMaxVector(raw string) map[string]string {
	out := make(map[string]string, 16)
	for _, part := range strings.Split(strings.TrimSuffix(raw, "/"), "/") {
		if key, value, ok := strings.Cut(part, ":"); ok {
			out[key] = value
		}
	}
	return out
}

func v4Score(metrics map[string]string) float64 {
	sel := v4Metrics(metrics)
	// No impact on any system: the reference shortcut.
	none := true
	for _, metric := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if sel.m(metric) != "N" {
			none = false
			break
		}
	}
	if none {
		return 0.0
	}

	macro := sel.macroVector()
	value := v4LookupScore(macro)
	eq := make([]int, 6)
	for i := range eq {
		eq[i] = int(macro[i] - '0')
	}
	eq1, eq2, eq3, eq4, eq5, eq6 := eq[0], eq[1], eq[2], eq[3], eq[4], eq[5]

	scoreEQ1Lower := v4LookupScore(macroOf(eq1+1, eq2, eq3, eq4, eq5, eq6))
	scoreEQ2Lower := v4LookupScore(macroOf(eq1, eq2+1, eq3, eq4, eq5, eq6))
	var scoreEQ3EQ6Lower float64
	switch {
	case eq3 == 1 && eq6 == 1, eq3 == 0 && eq6 == 1:
		scoreEQ3EQ6Lower = v4LookupScore(macroOf(eq1, eq2, eq3+1, eq4, eq5, eq6))
	case eq3 == 1 && eq6 == 0:
		scoreEQ3EQ6Lower = v4LookupScore(macroOf(eq1, eq2, eq3, eq4, eq5, eq6+1))
	case eq3 == 0 && eq6 == 0:
		// Two paths down; the higher score wins (a NaN compares false, as
		// in the reference, which then takes the right-hand path).
		left := v4LookupScore(macroOf(eq1, eq2, eq3, eq4, eq5, eq6+1))
		right := v4LookupScore(macroOf(eq1, eq2, eq3+1, eq4, eq5, eq6))
		if left > right {
			scoreEQ3EQ6Lower = left
		} else {
			scoreEQ3EQ6Lower = right
		}
	default:
		scoreEQ3EQ6Lower = v4LookupScore(macroOf(eq1, eq2, eq3+1, eq4, eq5, eq6+1))
	}
	scoreEQ4Lower := v4LookupScore(macroOf(eq1, eq2, eq3, eq4+1, eq5, eq6))
	scoreEQ5Lower := v4LookupScore(macroOf(eq1, eq2, eq3, eq4, eq5+1, eq6))

	// Compose the MacroVector's highest-severity vectors.
	var maxVectors []string
	for _, a := range v4MaxEQ1[eq1] {
		for _, b := range v4MaxEQ2[eq2] {
			for _, c := range v4MaxEQ3EQ6[eq3][eq6] {
				for _, d := range v4MaxEQ4[eq4] {
					for _, e := range v4MaxEQ5[eq5] {
						maxVectors = append(maxVectors, a+b+c+d+e)
					}
				}
			}
		}
	}

	// The first highest vector the scored one does not exceed. As in the
	// reference, if none fits the last one's distances are used.
	var dAV, dPR, dUI, dAC, dAT, dVC, dVI, dVA, dSC, dSI, dSA, dCR, dIR, dAR float64
	for _, raw := range maxVectors {
		max := parseMaxVector(raw)
		dAV = v4AVLevels[sel.m("AV")] - v4AVLevels[max["AV"]]
		dPR = v4PRLevels[sel.m("PR")] - v4PRLevels[max["PR"]]
		dUI = v4UILevels[sel.m("UI")] - v4UILevels[max["UI"]]
		dAC = v4ACLevels[sel.m("AC")] - v4ACLevels[max["AC"]]
		dAT = v4ATLevels[sel.m("AT")] - v4ATLevels[max["AT"]]
		dVC = v4VCLevels[sel.m("VC")] - v4VCLevels[max["VC"]]
		dVI = v4VILevels[sel.m("VI")] - v4VILevels[max["VI"]]
		dVA = v4VALevels[sel.m("VA")] - v4VALevels[max["VA"]]
		dSC = v4SCLevels[sel.m("SC")] - v4SCLevels[max["SC"]]
		dSI = v4SILevels[sel.m("SI")] - v4SILevels[max["SI"]]
		dSA = v4SALevels[sel.m("SA")] - v4SALevels[max["SA"]]
		dCR = v4CRLevels[sel.m("CR")] - v4CRLevels[max["CR"]]
		dIR = v4IRLevels[sel.m("IR")] - v4IRLevels[max["IR"]]
		dAR = v4ARLevels[sel.m("AR")] - v4ARLevels[max["AR"]]
		negative := false
		for _, distance := range []float64{dAV, dPR, dUI, dAC, dAT, dVC, dVI, dVA, dSC, dSI, dSA, dCR, dIR, dAR} {
			if distance < 0 {
				negative = true
				break
			}
		}
		if !negative {
			break
		}
	}

	currentEQ1 := dAV + dPR + dUI
	currentEQ2 := dAC + dAT
	currentEQ3EQ6 := dVC + dVI + dVA + dCR + dIR + dAR
	currentEQ4 := dSC + dSI + dSA

	const step = 0.1
	availableEQ1 := value - scoreEQ1Lower
	availableEQ2 := value - scoreEQ2Lower
	availableEQ3EQ6 := value - scoreEQ3EQ6Lower
	availableEQ4 := value - scoreEQ4Lower
	availableEQ5 := value - scoreEQ5Lower

	maxSeverityEQ1 := v4MaxSeverityEQ1[eq1] * step
	maxSeverityEQ2 := v4MaxSeverityEQ2[eq2] * step
	maxSeverityEQ3EQ6 := v4MaxSeverityEQ3EQ6[eq3][eq6] * step
	maxSeverityEQ4 := v4MaxSeverityEQ4[eq4] * step

	existing := 0
	var normalizedEQ1, normalizedEQ2, normalizedEQ3EQ6, normalizedEQ4, normalizedEQ5 float64
	if !math.IsNaN(availableEQ1) {
		existing++
		normalizedEQ1 = availableEQ1 * (currentEQ1 / maxSeverityEQ1)
	}
	if !math.IsNaN(availableEQ2) {
		existing++
		normalizedEQ2 = availableEQ2 * (currentEQ2 / maxSeverityEQ2)
	}
	if !math.IsNaN(availableEQ3EQ6) {
		existing++
		normalizedEQ3EQ6 = availableEQ3EQ6 * (currentEQ3EQ6 / maxSeverityEQ3EQ6)
	}
	if !math.IsNaN(availableEQ4) {
		existing++
		normalizedEQ4 = availableEQ4 * (currentEQ4 / maxSeverityEQ4)
	}
	if !math.IsNaN(availableEQ5) {
		// EQ5's proportion is always 0.
		existing++
		normalizedEQ5 = availableEQ5 * 0
	}

	meanDistance := 0.0
	if existing > 0 {
		meanDistance = (normalizedEQ1 + normalizedEQ2 + normalizedEQ3EQ6 + normalizedEQ4 + normalizedEQ5) / float64(existing)
	}
	value -= meanDistance
	if value < 0 {
		value = 0.0
	}
	if value > 10 {
		value = 10.0
	}
	return math.Round(value*10) / 10
}
