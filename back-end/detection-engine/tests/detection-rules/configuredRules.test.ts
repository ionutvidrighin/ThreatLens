import { describe, expect, it } from "vitest"
import { evaluateForBruteForceAttack } from "../../src/detection-rules/evaluationAttacks/bruteForceAttack"
import { evaluateForPasswordSprayingAttack } from "../../src/detection-rules/evaluationAttacks/passwordSprayingAttack"
import {
 BRUTE_FORCE_RULE_ID,
 makeConfig,
 makeEvent,
 makeFailures,
 PASSWORD_SPRAYING_RULE_ID,
} from "../helpers"

// Rules that evaluate failed logins. Success-after-failures has different
// semantics (successful event, same-user failures) and has its own test file.
const rules = [
 { id: BRUTE_FORCE_RULE_ID, evaluate: evaluateForBruteForceAttack },
 { id: PASSWORD_SPRAYING_RULE_ID, evaluate: evaluateForPasswordSprayingAttack },
]

describe.each(rules)("configured rule $id", ({ id, evaluate }) => {
 it("uses the configured threshold, severity and window", () => {
  const event = makeEvent()
  const history = makeFailures(["alice", "bob"])
  const config = makeConfig(id, { threshold: 2, windowSeconds: 180, severity: "critical" })
  const result = evaluate(event, history, config)
  expect(result.detected).toBe(true)
  if (!result.detected) throw new Error("Expected a finding")
  expect(result.finding).toMatchObject({ ruleId: id, severity: "critical", windowSeconds: 180 })
  expect(evaluate(event, history, { ...config, threshold: 3 })).toEqual({ detected: false })
 })

 it("includes both boundaries and excludes older, future and invalid timestamps", () => {
  const event = makeEvent()
  const config = makeConfig(id, { threshold: 2, windowSeconds: 60 })
  const times = [event.time - 60_000, event.time, event.time - 60_001, event.time + 1]
  const history = makeFailures(["start", "end", "old", "future", "invalid"])
   .map((failure, i) => ({ ...failure, eventTime: i === 4 ? "invalid" : new Date(times[i]).toISOString() }))
  const result = evaluate(event, history, config)
  expect(result.detected).toBe(true)
  if (!result.detected) throw new Error("Expected a finding")
  expect(result.finding.metadata).toEqual(id === BRUTE_FORCE_RULE_ID
   ? { failedAttempts: 2, usernames: ["start", "end"] }
   : { targetedAccounts: 2, usernames: ["start", "end"] })
  expect(evaluate(event, history, { ...config, threshold: 3 })).toEqual({ detected: false })
 })

})
