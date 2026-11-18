# Testing

What "the client works" means, which test shows each part of it, how we
know those tests can fail, and what is not tested. The requirements (IDs
F, Q, C) are in
[opnsense-api-spec/docs/requirements.md](https://github.com/pipiobjo/opnsense-api-spec/blob/main/docs/requirements.md).

## What has to be true

The client is correct when these claims hold on every supported OPNsense
series (25.7, 26.1, 26.7), core and plugins:

| # | Claim | Requirement |
|---|---|---|
| K1 | It finds out which core and plugin versions the firewall runs and resolves each to the data that describes it; it never uses data newer than the installed version and refuses a series it has no data for. | F2 |
| K2 | Nothing is sent that the resolved version does not have: unknown resources, fields, operations, option values, wrongly typed values, and fields the firewall sets itself are refused before a request leaves. | F6 |
| K3 | A write that did not take effect is an error: every add and set is read back and compared; toggle and delete are confirmed. | F6 |
| K4 | It reads every resource the data marks as verified, on a real firewall, and decodes the values. | F1, F2 |
| K5 | It treats OPNsense's answer shapes and conventions correctly (option maps, empty objects as `[]`, IDs that are not UUIDs, uncounted rows, silent deletes, blank templates for unknown IDs). | F6 |
| K6 | Credentials stay secret and the connection is authenticated: TLS verified by default, pin or CA as configured, no redirects, credentials never in errors or logs, field values never in error text (they may be secrets), no input can leave the API path. | Q2 |
| K7 | Crafted capability data or crafted answers cannot crash the client or make it read outside its data directory. | Q2 |
| K8 | What the fake firewall in the unit tests assumes about OPNsense is still true. | Q1 |
| K9 | In read-only mode nothing that changes the firewall is sent, by two independent checks (the API methods and the transport), and every read keeps working. | F7 |

## Test layers

| Layer | Where | Runs | Shows | Cannot show |
|---|---|---|---|---|
| Unit tests against a fake firewall | `opnsense/*_test.go`, `internal/transport/*_test.go` | every `go test`, every push and pull request | each rule, error, refusal and TLS mode, including that a refused write sent nothing | whether OPNsense really behaves like the fake (that is K8) |
| Unit tests on real data | `opnsense/capability/*_test.go` with data of all 35 core versions (`testdata/`, trimmed by `tools/testdata.sh`) | same | resolution over the real version history; value encoding; the model matches the format's schema | behaviour of a live firewall |
| Fuzz targets | `FuzzWireDecode`, `FuzzLoad`, `FuzzCheckID`, `FuzzCheckPath` | seeds with every `go test`; 10 s of generated input per target in CI | no panic, no path escape, for any input; generic, so they need no change when OPNsense's API changes | logic errors that do not crash |
| Vulnerability check | `tools/ci/vulncheck.sh` (govulncheck) | every push, pull request and release, and after new spec data | no known vulnerability with a fix in code the client calls, for the Go release CI builds with | vulnerabilities not yet known |
| Recorded behaviour | `test/integration/recorded_test.go` | integration runs | the fake's assumptions, checked with raw HTTP calls that bypass the client | — |
| Integration | `test/integration/integration_test.go` on a throwaway VM with every plugin | every push and pull request, and when the spec publishes new data; newest release of each series | the client end to end on every verified resource | resources without a verified sample; older releases of a series |

The integration tests run only against a VM on `127.0.0.1` (C1). They
refuse any other target.

## Claims and their tests

| Claim | Tests |
|---|---|
| K1 | `TestDetectExact`, `TestDetectHotfixIsANote`, `TestDetectAssumedAndRefused`, `TestDetectionFallbackOnlyOnForbidden`, `TestDetectionWithoutFirmwarePrivilege`, `TestResolveReal`, `TestResolveRefuse`, `TestResolveNearestOlderCore`, `TestResolveCoreNeverNewer`, `TestResolveNewerSeriesIsTypedError`, `TestResolvePluginBetweenKnownVersions`, `TestResolvePluginOlderThanData`, `TestResolveCoreOlderThanData`, `TestRefuseCoversPackageWithoutSeriesData`, `TestResolveOtherCoresOnlyIsANote`, `TestCompareVersions` (same table as the spec), `TestVersionsWithLetters`, `TestReadOnlyPackageRefusesWrites`, `TestInstanceIsACopy`; on the VM `TestDetectionResolves` |
| K2 | `TestNothingIsSentThatTheVersionDoesNotHave`, `TestCheck`, `TestInfo`, `TestFieldOfAnotherVersion`, `TestResourceNotAvailable`, `TestEncode`, `TestServerSetFieldsAndOptionLists`, `TestVolatileRefusedTransformedChecked`, `TestTypedErrors`, `TestFieldsAndGetRaw`, `TestValidationFromTheFirewall` |
| K3 | `TestEntriesCycle`, `TestSettings`, `TestReadBackCatchesWhatTheServerIgnored`, `TestSameWire`, `TestReadBackCause`, `TestToggle`, `TestToggleReadsBack`, `TestDeleteIsConfirmed`, `TestSilentDelete`, `TestTransformedFieldIsWrittenNotCompared`, `TestWriteOnlyFieldIsNotReadBack`, `TestAutoApply`, `TestAutoApplyAfterReadBack`, `TestApplyNeedsAnExplicitOK`, `TestApplyKeepsWritesDuringTheCall`, `TestLocksRespectTheContext`, `TestResourceApply`, `TestResourceApplyInANewProcess`, `TestLostAnswerMarksPending`, `TestPostOutcomeUnknown`; on the VM `TestOSPFNeighborCycle`, `TestSettingsSetAndRestore`, `TestEveryVerifiedResource` |
| K4 | `TestEveryVerifiedResource`, `TestWireAndDecode`, `TestOneOddFieldDoesNotHideTheOthers`, `TestWriteOnlyFieldsAreNotDecoded`, `TestRealDataFieldsAndVariants` |
| K5 | `TestBadIDsAreRefused`, `TestNonUUIDIDsAreAccepted`, `TestBlankTemplateIsNotAnEntry`, `TestGetFullTemplateIsNotFound`, `TestListPagesAndGetOnlySearch`, `TestListNoticesMissingRows`, `TestSearchWithUncountedRows`, `TestApplyAcceptsResultOK`, `TestSetPath`, `TestCall` |
| K6 | `TestTLSPinAndAuth`, `TestTLSWithCA`, `TestHTTPClientWithTLSIsRefused`, `TestCredentialsNeverInErrorsOrLogs`, `TestValuesNeverInErrorMessages`, `TestBrokenJSONIsNotQuoted`, `TestConfigChecks`, `TestQueryRedirectAndSize`, `TestErrorsAndRequestShape`, `TestGetIsRetriedPostIsNot`, `TestReadRetries`, `TestDefaultTransportUsesHTTP2`, `TestUnauthorizedAndForbiddenDiffer`, `TestCheckPath`, `FuzzCheckPath`, `FuzzCheckID` |
| K7 | `TestLoadBounded`, `TestCapabilityDirSymlinkOutside`, `TestLoadRefusesEscapingFileNames`, `TestLoadRefusesOtherFormat`, `TestCheckFindsBrokenReferences`, `TestCheckNullEntriesWithoutPanic`, `TestBrokenDataIsAnErrorNotAPanic`, `TestModelMatchesSchema`, `FuzzLoad`, `FuzzWireDecode` |
| K9 | `TestReadOnlyMode` (every changing method refused, only GETs and the search POST reach the fake, its state unchanged), `TestReadOnlyConfig`, `TestReadOnlyTransport` (the transport alone refuses every other POST and every GET outside its list); on the VM `TestReadOnlyClientChangesNothing` (every resource read, every change refused, `config.xml` byte-identical afterwards) |
| K8 | `TestRecordedBehaviour` (unknown keys ignored with "saved", `[]` for an unknown UUID, set creates under an unknown UUID, GET with `Content-Type` rejected, search totals, apply answer), `TestFakeSpeaksHTTP2` |

Error messages, which a provider shows its users, are checked by
`TestErrorMessages`. `TestEveryTestIsDocumented` fails when a test exists
that this page does not name, or the page names one that does not exist.

## How we know a test can fail

A test that cannot fail proves nothing (Q1). Every rule was introduced
with a test that was seen failing first, and every new or changed check is
broken on purpose once: the code under test is changed so the claim
becomes false, the test must go red, then the change is reverted. Examples
from the history: removing either check of the read-only mode (the other
one still holds; with both removed, the fake and the VM report the
writes), removing the container check from `setPath`, letting the
transport log the secret or put the key into an error, accepting a CA that
did not sign the server certificate, a renamed JSON key in the data model.
Commit messages record these checks ("seen failing for ...").

## The integration test in detail

`TestEveryVerifiedResource` takes every resource the capability data
marks as verified on the VM's version and exercises it through the
public API:

- entry lists with the verified sample: add, get, set with read-back,
  list, delete, and a check that the entry is gone;
- settings the spec's contract test wrote: read, then set one boolean
  field to the other value and back, each with read-back, so a stored
  write is told from an ignored one. If the resource is stored through its
  own code (`custom-save`) and that ignores the field in its current
  state, the next boolean field is tried; each attempt is logged;
- settings the contract test only read: read;
- every apply endpoint that became pending.

It compares every field it sent. The only tolerated difference is one the
data explains with `custom-save` on a field neither the contract test nor
this test chose on purpose; each is logged. Apply endpoints may fail only
if they are listed with a reason and series in
[`test/integration/apply-failures.json`](../test/integration/apply-failures.json)
(services that cannot run on the isolated VM: no internet, no hardware); an
entry that works is reported for removal. Samples that refer to something
only the contract test's instance had are skipped with the reason.

Only subtests that ran to the end without failing count as tested; a
subtest that skips itself is counted apart. The tested count must reach
the floor of the series in
[`test/integration/tested-floor.txt`](../test/integration/tested-floor.txt)
(about 95 % of the last full run), so a run that lost verification data
or plugins fails instead of passing with little tested.

The read-only test reads every resource; a read that fails in read-only
mode but works without it fails the test (the transport's read list would
be too narrow).

Results of the most recent full run (local VMs with KVM, every plugin
installed, spec data 0.9.3, 2026-11-18). Earlier figures (299, 307, 314
"resources tested") also counted settings that were only read and
subtests that skipped themselves; they are not comparable.

| Release | Written and read back | Settings only read | Skipped themselves | Entry lists without a usable sample | Tolerated differences | Read-only test: reads | Failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| 25.7.11_9 | 222 | 72 | 5 | 46 | 0 | 350 | 0 |
| 26.1.11_10 | 226 | 75 | 6 | 48 | 0 | 357 | 0 |
| 26.7.9_3 | 230 | 79 | 5 | 53 | 1 | 369 | 0 |

The subtests that skip themselves do so with a reason in the log: no
boolean field to change (`firewall/alias`, the plugin authentication
settings), the model not valid in its default state on the VM
(`core/initial_setup`, whose own save code also ignores most boolean
fields), or a sample that refers to the contract test's instance.

## Coverage

Coverage is measured with `-coverpkg=./...`, so code counts wherever a
test reaches it. `tools/ci/coverage.sh` writes a table per package to the
CI summary and an HTML report as the artifact `coverage-unit`
(`coverage-integration-<release>` for the VM runs). It fails when a total
drops below its floor in `tools/ci/coverage-floor.txt`.

| Profile | Statements covered | Floor |
|---|---:|---:|
| unit | 91.2% | 91% |
| integration (per release, alone; includes the read-only test) | 62.9% to 65.9% (26.7.9: 64.9% on 2026-11-18) | 62% |
| unit and integration together | 91.9% | — |

Coverage says which code ran, not whether its result was checked; the
claims and the deliberate breaks above are what make the tests count.
Code not reached by unit tests is mostly string formatting
(`Match.String`) and a JSON marshaller nothing calls on the client side.

## What is not tested

- Entry lists without a verified sample (46 to 53 per series) are only
  read in the integration test, not written: the spec's contract test
  found no value the firewall accepted for them (they need other objects,
  certificates or hardware first).
- Only the newest release of each series runs on a VM. Older releases
  rely on the data, the resolver tests and read-back at run time.
- Option lists that OPNsense fills at run time (interfaces, certificates)
  are not checked before sending; the firewall's validation reports them.
- A plugin that does not install on the test VM is a warning, not a
  failure: its resources are not tested in that run, the run summary
  names it, and its complete firmware log is kept as the artifact
  `logs-<release>`. (One such case so far, 2026-11-17, 25.7.11: two
  plugins; the next run installed all.)
- Business editions are not tested (no public images).

## Running the tests

[CONTRIBUTING.md](../CONTRIBUTING.md) has the commands for unit tests,
coverage and the integration run on a throwaway VM.
