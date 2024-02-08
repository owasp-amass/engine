// Copyright © by Tim Rose 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import "testing"
import "sort"
import "slices"
//import "github.com/owasp-amass/engine/plugins/support/resolvers"
// import "github.com/owasp-amass/engine/tree/develop/plugins/support/support"

type flipWordTest struct {
	addedWords      []string
	domain          string
	expectedDomains []string
}

var flipWordTests = []flipWordTest{
	flipWordTest{[]string{"x0", "x1"}, "a-b-c.com", []string{"a-b-x0.com", "a-b-x1.com", "x0-b-c.com", "x1-b-c.com"}},
	flipWordTest{[]string{"x0"}, "mysubdomain.subdomain2.mydomain.com", []string{}},
	flipWordTest{[]string{"suf", "pre"}, "mysubdomain-subdomain2-subdomain3-mydomain.com",
		[]string{"mysubdomain-subdomain2-subdomain3-pre.com", "mysubdomain-subdomain2-subdomain3-suf.com", "pre-subdomain2-subdomain3-mydomain.com", "suf-subdomain2-subdomain3-mydomain.com"}},
}

func TestFlipWords(t *testing.T) {

	for _, test := range flipWordTests {
		result := flipWords(test.domain, test.addedWords)

		if len(result) > 0 {
			// Sort the Slices for easier comparison
			sort.Strings(result)
			sort.Strings(test.expectedDomains)
			for i := 0; i < len(result); i++ {
				if result[i] != test.expectedDomains[i] {
					t.Errorf("got %s, wanted %s", result[i], test.expectedDomains[i])
				}
			}
		} else {
			if len(test.expectedDomains) != 0 {
				t.Errorf("unexpected empty result")
			}
		}
	}
}

/*********************************************************************/

type flipNumberTest struct {
	domain          string
	expectedDomains []string
}

var flipNumberTests = []flipNumberTest{
	flipNumberTest{"a9-b8-c7.com", []string{"a4-b8-c7.com", "a6-b8-c.com", "a7-b8-c3.com", "a0-b8-c7.com", "a2-b8-c6.com", "a2-b8-c8.com", "a4-b8-c2.com"}},
	flipNumberTest{"mysubdomain.subdomain2.mydomain.com", []string{}},
	flipNumberTest{"mysubdomain-subdomain2-subdomain3-mydomain.com",
		[]string{"mysubdomain-subdomain9-subdomain-mydomain.com", "mysubdomain-subdomain6-subdomain7-mydomain.com", "mysubdomain-subdomain4-subdomain4-mydomain.com", "mysubdomain-subdomain5-subdomain1-mydomain.com"}},
}

func TestFlipNumber(t *testing.T) {

	for _, test := range flipNumberTests {
		result := flipNumbers(test.domain)

		if len(result) > 0 {
			// This result contains a large number of permutations. The expectedDomains list contain a subset of the possible values as a spot check.
			for i := 0; i < len(test.expectedDomains); i++ {
				if slices.Contains(result, test.expectedDomains[i]) == false {
					t.Errorf("Did not find %s in resultset", test.expectedDomains[i])
				}
			}
		} else {
			if len(test.expectedDomains) != 0 {
				t.Errorf("unexpected empty result")
			}
		}
	}
}

/*********************************************************************/

type fuzzyLabelSearchesTest struct {
	name              string
	distance          int
	charsForSomething string
	expectedStrings   []string
}

var fuzzyLabelSearchesTests = []fuzzyLabelSearchesTest{
	fuzzyLabelSearchesTest{"zz.yy.xx.vv", 1, "abc", []string{"cca.yy.xx.vv", "ccc.yy.xx.vv", "z.yy.xx.vv", "zz.yy.xx.vv", "ca.yy.xx.vv", "bz.yy.xx.vv"}},
	fuzzyLabelSearchesTest{"subdomain.domain", 3, "z", []string{"zzzzzdddd.domain", "zzzmiiiii.domain", "zzzzzzsuu.domain", "zzdmaaaa.domain", "udmiiiii.domain", "zzzzzzzsubdo.domain"}},
	fuzzyLabelSearchesTest{"domain", 10, "abc", []string{}},
}

func TestFuzzyLabelSearches(t *testing.T) {
	for _, test := range fuzzyLabelSearchesTests {
		result := fuzzyLabelSearches(test.name, test.distance, test.charsForSomething)

		if len(result) > 0 {
			// This result contains a large number of permutations. The expectedStrings list contain a subset of the possible values as a spot check.
			for i := 0; i < len(test.expectedStrings); i++ {
				if slices.Contains(result, test.expectedStrings[i]) == false {
					t.Errorf("Did not find %s in resultset", test.expectedStrings[i])
				}
			}
		} else {
			if len(test.expectedStrings) != 0 {
				t.Errorf("unexpected empty result")
			}
		}
	}
}

/*********************************************************************/

type addSuffixWordTest struct {
	addedWords      []string
	domain          string
	expectedDomains []string
}

var addSuffixWordTests = []addSuffixWordTest{
	addSuffixWordTest{[]string{"x0", "x1"}, "a-b-c.com", []string{"a-b-cx1.com", "a-b-c-x0.com", "a-b-c-x1.com", "a-b-cx0.com"}},
	addSuffixWordTest{[]string{"x0"}, "mysubdomain.subdomain2.mydomain.com", []string{"mysubdomain-x0.subdomain2.mydomain.com", "mysubdomainx0.subdomain2.mydomain.com"}},
	addSuffixWordTest{[]string{"suf"}, "mysubdomain-subdomain2-subdomain3-mydomain.com", []string{"mysubdomain-subdomain2-subdomain3-mydomainsuf.com", "mysubdomain-subdomain2-subdomain3-mydomain-suf.com"}},
}

func TestAddSuffixWords(t *testing.T) {
	for _, test := range addSuffixWordTests {
		result := addSuffixWords(test.domain, test.addedWords)

		if len(result) > 0 {
			// Sort the Slices for easier comparison
			sort.Strings(result)
			sort.Strings(test.expectedDomains)
			for i := 0; i < len(result); i++ {
				if result[i] != test.expectedDomains[i] {
					t.Errorf("got %s, wanted %s", result[i], test.expectedDomains[i])
				}
			}
		} else {
			if len(test.expectedDomains) != 0 {
				t.Errorf("unexpected empty result")
			}
		}
	}
}

/*********************************************************************/

type addPrefixWordTest struct {
	addedWords      []string
	domain          string
	expectedDomains []string
}

var addPrefixWordTests = []addPrefixWordTest{
	addPrefixWordTest{[]string{"x0", "x1"}, "a-b-c.com", []string{"x0-a-b-c.com", "x0a-b-c.com", "x1-a-b-c.com", "x1a-b-c.com"}},
	addPrefixWordTest{[]string{"x0"}, "mysubdomain.subdomain2.mydomain.com", []string{"x0-mysubdomain.subdomain2.mydomain.com", "x0mysubdomain.subdomain2.mydomain.com"}},
	addPrefixWordTest{[]string{"pre"}, "mysubdomain-subdomain2-subdomain3-mydomain.com",
		[]string{"pre-mysubdomain-subdomain2-subdomain3-mydomain.com", "premysubdomain-subdomain2-subdomain3-mydomain.com"}},
}

func TestAddPrefixWords(t *testing.T) {
	for _, test := range addPrefixWordTests {
		result := addPrefixWords(test.domain, test.addedWords)

		if len(result) > 0 {
			// Sort the Slices for easier comparison
			sort.Strings(result)
			sort.Strings(test.expectedDomains)
			for i := 0; i < len(result); i++ {
				if result[i] != test.expectedDomains[i] {
					t.Errorf("got %s, wanted %s", result[i], test.expectedDomains[i])
				}
			}
		} else {
			if len(test.expectedDomains) != 0 {
				t.Errorf("unexpected empty result")
			}
		}
	}
}
