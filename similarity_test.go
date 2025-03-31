package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// generateSimilarityReport generates a detailed report of username similarities
func generateSimilarityReport(testNames []string, similarityThreshold, autoMuteThreshold float64) string {
	var resultBuilder strings.Builder
	resultBuilder.WriteString("Username Similarity Test Results\n\n")
	resultBuilder.WriteString(fmt.Sprintf("Similarity threshold: %.2f\nAuto-mute threshold: %.2f\n\n",
		similarityThreshold, autoMuteThreshold))
	resultBuilder.WriteString("Test Name | Similar To | Similarity | Action\n")
	resultBuilder.WriteString("---------------------------------------------\n")

	// Track maximum width for name column to align table
	maxNameLen := 0
	for _, name := range testNames {
		if len(name) > maxNameLen {
			maxNameLen = len(name)
		}
	}

	// Check each test name against known usernames
	for _, testName := range testNames {
		var highestSimilarity float64
		var mostSimilarName string

		// Check against all known usernames
		for _, knownName := range KnownUsernames {
			similarity := JaroWinkler(testName, knownName)

			// Track the highest similarity
			if similarity > highestSimilarity {
				highestSimilarity = similarity
				mostSimilarName = knownName
			}
		}

		// Format padding for name column
		namePadding := strings.Repeat(" ", maxNameLen-len(testName))

		// Determine action based on similarity
		action := "None"
		if highestSimilarity >= similarityThreshold {
			action = "Alert"
		}
		if highestSimilarity >= autoMuteThreshold {
			action = "Auto-Mute"
		}

		// Add this test result to the table
		resultBuilder.WriteString(fmt.Sprintf("%s%s | %s | %.1f%% | %s\n",
			testName, namePadding,
			mostSimilarName,
			highestSimilarity*100,
			action))
	}

	return resultBuilder.String()
}

// TestDeveloperUsernameSimilarity tests usernames of the developers and contributors
func TestDeveloperUsernameSimilarity(t *testing.T) {
	// Save original KnownUsernames and restore after test
	originalUsernames := KnownUsernames
	defer func() { KnownUsernames = originalUsernames }()

	// Set known usernames for testing
	KnownUsernames = []string{
		"alephium",
		"alph_official",
		"alephium_org",
		"alph_foundation",
		"cgi_bin",
		"cgibin",
		"diomark0",
		"babyxdd",
		"MaudBannwart",
		"polto",
		"vladm9",
		"ratko42",
		"wachmc",
		"mikae",
		"nop_33",
		"h0ngcha0",
		"hongcha0",
	}

	// Test similar usernames
	testUsernames := []string{
		"cg1_bin", "cgi_b1n", "cgl_bin", "cgi-bln", "c91_bin", "cqi_bin", "cgj_bin",
		"cl_bin", "c_gi_bin", "cgii_bin", "cgib1n", "cglb1n", "cg1bln",

		"dlomark0", "di0marko", "diomarkO", "diomarkQ", "d1omark0", "diomark_",
		"di0m4rk0", "d1o_mark0", "diomar_k0", "di0mark_zero",

		"b4byxdd", "baby_xdd", "babyx_d", "babyyxdd", "b4by_xdd", "b_a_b_yxdd",
		"babyxddd", "bbyxdd", "babbyxdd", "ba_by_xdd", "bqbyxdd",

		"MaudBannw4rt", "Maud_Bannwart", "M4udBannwart", "MaudB4nnwart",
		"MaudBannw@rt", "MaudBannwa_rt", "MaudBann_wart", "Maud_B4nnwart",
		"Maud_Banw4rt",

		"p0lto", "poIto", "po1to", "polt0", "p0l_to", "p0lt0_", "p_olto",
		"pol_10", "polto_", "pol_t0",

		"v1adm9", "vIadm9", "vladmQ", "vlad_m9", "vlad_m_9", "vladm_9",
		"vl4dm9", "vladm_09", "vla_dm9", "vlad",

		"ratk042", "ratko_42", "r4tko42", "rattko42", "rat_k042", "r@tko42",
		"rattk042", "rat_k0_42", "ratko_4_2",

		"w4chmc", "wach_mc", "wachmC", "wa_chmc", "wachm_c", "w@chmc",
		"wachmc_", "wachmC_", "w4_chmc",

		"mik4e", "m1kae", "mika3", "mikae_", "mika_e", "mikaee", "m1k4e",
		"m_i_k_ae", "mika-3",

		"n0p_33", "nop_3_3", "nop33_", "nop-33", "n0p33", "n_op33", "n0p_3.3",
		"n0p-3_3", "nop_33_",

		"hOngchaO", "h0ngch4o", "h0ngchao_", "hongcha0", "h0ng_ch4o",
		"h0ngcha00", "h0ngch_ao", "h_ongchao", "h0_ngchaO",
	}

	// Generate similarity report
	reportContent := generateSimilarityReport(testUsernames, 0.93, 0.95)

	// Save to file for review
	if err := os.WriteFile("dev_similarity_test_report.txt", []byte(reportContent), 0644); err != nil {
		t.Errorf("Failed to save developer test report: %v", err)
	} else {
		t.Logf("Developer similarity test report saved to dev_similarity_test_report.txt")
	}

	// This test always passes - it's for generating the report
	t.Log("Developer username similarity test complete")
}
