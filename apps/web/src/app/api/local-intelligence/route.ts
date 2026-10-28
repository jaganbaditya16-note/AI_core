import { NextResponse } from "next/server";

import { isSameOriginRequest } from "@/lib/intelligence-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const revalidate = 0;

const MODEL = "llama3.2:1b";
const OLLAMA_URL = "http://127.0.0.1:11434/api/chat";
const MAX_BODY_BYTES = 8_000;
const MAX_LIST_ITEMS = 6;
const MAX_ITEM_LENGTH = 500;

const SYSTEM_PROMPT = `
You are a cautious security analyst assisting a human reviewer.

The supplied incident is a SYNTHETIC DEMONSTRATION, not live telemetry.
Never call a denial spike a denial-of-service attack unless the evidence
actually establishes that. Separate observed signals from possible causes.
Do not invent IP addresses, users, events, logs, attacks, or actions.
Do not approve, deny, execute, or change any security control.
Recommend safe, reversible, human-reviewed investigation steps.

Return a JSON object with exactly these keys:
advisory, likely_causes, safe_next_steps, questions_for_reviewer.

advisory must be a string. The other three fields must be arrays of strings.
Return at most 3 concise, non-repetitive items per list. Each item must be under 20 words. Never repeat an item. Keep the advisory to 1 or 2 sentences and state what the evidence does not establish.
`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= max
  );
}

function readStringList(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    value.length > 12 ||
    !value.every((item) => typeof item === "string")
  ) {
    return null;
  }

  return value
    .map((item: string) => item.trim().slice(0, MAX_ITEM_LENGTH))
    .filter(Boolean)
    .slice(0, MAX_LIST_ITEMS);
}

function fail(message: string, status: number) {
  return NextResponse.json(
    { error: message },
    { status, headers: { "cache-control": "no-store" } },
  );
}

export async function POST(request: Request) {
  // This endpoint is strictly for a local development demonstration.
  if (process.env.NODE_ENV !== "development") {
    return fail("Local advisory is available only in development", 404);
  }

  if (!isSameOriginRequest(request.url, request.headers.get("origin"))) {
    return fail("Forbidden request origin", 403);
  }

  const contentLength = Number.parseInt(
    request.headers.get("content-length") ?? "0",
    10,
  );

  if (contentLength > MAX_BODY_BYTES) {
    return fail("Request too large", 413);
  }

  let rawBody: string;
  try {
    rawBody = await request.text();
  } catch {
    return fail("Could not read request body", 400);
  }

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return fail("Request too large", 413);
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return fail("Invalid JSON", 400);
  }

  if (!isRecord(payload)) {
    return fail("Expected a structured incident object", 400);
  }

  const signals = payload.signals;

  if (
    !isBoundedString(payload.incident_type, 80) ||
    !isBoundedString(payload.risk_level, 24) ||
    !(
      payload.affected_agent === null ||
      payload.affected_agent === undefined ||
      isBoundedString(payload.affected_agent, 120)
    ) ||
    !Array.isArray(signals) ||
    signals.length > 12 ||
    !signals.every(
      (signal: unknown) =>
        isRecord(signal) &&
        isBoundedString(signal.name, 80) &&
        isBoundedString(signal.value, 500),
    )
  ) {
    return fail("Incident does not match the bounded advisory contract", 400);
  }

  const incident = {
    incident_type: payload.incident_type,
    risk_level: payload.risk_level,
    affected_agent: payload.affected_agent ?? null,
    signals: signals.map((signal: Record<string, unknown>) => ({
      name: signal.name,
      value: signal.value,
    })),
    context:
      "Synthetic demonstration only. Signals are illustrative, not live risk findings.",
    requested_focus:
      "Explain the supplied signals, distinguish hypotheses from facts, and recommend safe next steps.",
  };

  try {
    const response = await fetch(OLLAMA_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: MODEL,
        stream: false,
        format: {
          type: "object",
          properties: {
            advisory: { type: "string", minLength: 20, maxLength: 700 },
            likely_causes: {
              type: "array", maxItems: 3,
              items: { type: "string", maxLength: 220 },
            },
            safe_next_steps: {
              type: "array", maxItems: 3,
              items: { type: "string", maxLength: 220 },
            },
            questions_for_reviewer: {
              type: "array", maxItems: 3,
              items: { type: "string", maxLength: 220 },
            },
          },
          required: [
            "advisory",
            "likely_causes",
            "safe_next_steps",
            "questions_for_reviewer",
          ],
          additionalProperties: false,
        },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: JSON.stringify(incident) },
        ],
        options: {
          temperature: 0,
          num_predict: 400,
        },
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(90_000),
    });

    if (!response.ok) {
      return fail(
        "Local Ollama request failed. Check that Ollama is running and the model is available.",
        502,
      );
    }

    const envelope: unknown = await response.json();

    if (
      !isRecord(envelope) ||
      !isRecord(envelope.message) ||
      typeof envelope.message.content !== "string"
    ) {
      return fail("Local model returned an invalid response", 502);
    }

    let result: unknown;
    try {
      result = JSON.parse(envelope.message.content);
    } catch {
      console.error("[local-intelligence] Ollama returned non-JSON content");
      return fail(
        "Local model response was not valid JSON. Check the Next.js terminal for diagnostic output.",
        502,
      );
    }

    if (
      !isRecord(result) ||
      !isBoundedString(result.advisory, 4_000)
    ) {
      return fail("Local model response is missing a valid advisory", 502);
    }

    const likelyCauses = readStringList(result.likely_causes);
    const safeNextSteps = readStringList(result.safe_next_steps);
    const reviewerQuestions = readStringList(result.questions_for_reviewer);

    if (likelyCauses === null || safeNextSteps === null || reviewerQuestions === null) {
      return fail("Local model returned invalid advisory lists", 502);
    }

    return NextResponse.json(
      {
        provider: "local-ollama-development",
        model: MODEL,
        generated_at: new Date().toISOString(),
        advisory: result.advisory.trim().slice(0, 4_000),
        likely_causes: likelyCauses,
        safe_next_steps: safeNextSteps,
        questions_for_reviewer: reviewerQuestions,
        safety_note:
          "Local model advisory based on synthetic signals. Possible causes are unverified. Deterministic AICore policy and firewall decisions remain authoritative.",
      },
      { headers: { "cache-control": "no-store" } },
    );
  } catch {
    return fail(
      "Local advisory failed. Verify that Ollama is running on 127.0.0.1:11434.",
      502,
    );
  }
}
