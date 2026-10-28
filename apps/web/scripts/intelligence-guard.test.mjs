import assert from "node:assert/strict";
import test from "node:test";

import {
  isIntelligenceRouteEnabled,
  isSameOriginRequest,
} from "../src/lib/intelligence-guard.ts";

test("development remains enabled without a public deployment flag", () => {
  assert.equal(isIntelligenceRouteEnabled("development", undefined), true);
});

test("production is disabled unless explicitly enabled", () => {
  assert.equal(isIntelligenceRouteEnabled("production", undefined), false);
  assert.equal(isIntelligenceRouteEnabled("production", "false"), false);
  assert.equal(isIntelligenceRouteEnabled("production", "true"), true);
});

test("accepts an exact same-origin request", () => {
  assert.equal(
    isSameOriginRequest(
      "https://aicore.example/api/intelligence",
      "https://aicore.example",
    ),
    true,
  );
});

test("rejects foreign, missing, malformed, or non-origin values", () => {
  const requestUrl = "https://aicore.example/api/intelligence";

  assert.equal(isSameOriginRequest(requestUrl, "https://attacker.example"), false);
  assert.equal(isSameOriginRequest(requestUrl, null), false);
  assert.equal(isSameOriginRequest(requestUrl, "not a URL"), false);
  assert.equal(isSameOriginRequest(requestUrl, "https://aicore.example/path"), false);
});
