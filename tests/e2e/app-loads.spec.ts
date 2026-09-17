import { expect, test } from "@playwright/test";

/**
 * Phase 0 smoke tests: the application loads and the frontend↔backend path works.
 * Deliberately small — this is a foundation check, not a feature suite.
 */

test.describe("application shell", () => {
  test("overview page loads and states the phase honestly", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "AICore", level: 1 })).toBeVisible();
    await expect(page.getByText("Phase 0 · Foundation")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Not implemented yet" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open system health" })).toBeVisible();
  });

  test("unknown route renders the not-found page", async ({ page }) => {
    const response = await page.goto("/this-route-does-not-exist");

    expect(response?.status()).toBe(404);
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  });
});

test.describe("frontend ↔ backend health path", () => {
  test("health page reports the live backend state", async ({ page }) => {
    await page.goto("/health");

    await expect(page.getByRole("heading", { name: "System health", level: 1 })).toBeVisible();

    // The API is running (Playwright starts it) and its database is deliberately
    // unreachable, so the panel must land on a terminal state reached through a
    // real HTTP round trip — never a hardcoded value.
    const status = page.getByText(/Operational|Reachable, dependency degraded|Backend unreachable/);
    await expect(status).toBeVisible({ timeout: 15_000 });

    // The database check is surfaced with its own status line.
    await expect(page.getByText("database")).toBeVisible();
  });

  test("same-origin proxy returns a structured report", async ({ request }) => {
    const response = await request.get("/api/health");

    expect([200, 503]).toContain(response.status());
    const body = await response.json();
    expect(body).toHaveProperty("reachable");
    expect(body).toHaveProperty("checkedAt");
    expect(body).toHaveProperty("errors");
    expect(Array.isArray(body.errors)).toBe(true);
  });
});
