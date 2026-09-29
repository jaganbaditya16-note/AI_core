import { expect, test } from "@playwright/test";

test.describe("application shell", () => {
  test("overview page presents the security intelligence product", async ({ page }) => {
    await page.goto("/");

    await expect(
      page.getByRole("heading", {
        name: "AI security decisions stay deterministic. Intelligence stays human-controlled.",
        level: 1,
      }),
    ).toBeVisible();
    await expect(page.getByText("AICore · Security Intelligence")).toBeVisible();
    await expect(page.getByText("NVIDIA Nemotron via Nebius Token Factory · human review")).toBeVisible();
    await expect(page.getByRole("link", { name: "Open security operations" })).toBeVisible();
    await expect(page.getByText("The model is advisory — never the authorization authority.")).toBeVisible();
  });

  test("unknown route renders the not-found page", async ({ page }) => {
    const response = await page.goto("/this-route-does-not-exist");

    expect(response?.status()).toBe(404);
    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
  });

  test("security operations dashboard exposes the human-review workflow", async ({ page }) => {
    await page.goto("/operations");

    await expect(page.getByRole("heading", { name: "Proof-Bound AI Security" })).toBeVisible();
    await expect(page.getByText("Deterministic controls detect and enforce.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Investigate with Nemotron" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Human Approval Queue" })).toBeVisible();

    await page.getByRole("button", { name: "Human Approval Queue" }).click();
    await expect(page.getByRole("heading", { name: "Human approval queue" })).toBeVisible();
    await expect(page.getByText("Separation of duties: reviewers cannot approve their own requests.")).toBeVisible();
  });
});

test.describe("frontend ↔ backend health path", () => {
  test("health page reports the live backend state", async ({ page }) => {
    await page.goto("/health");

    await expect(page.getByRole("heading", { name: "System health", level: 1 })).toBeVisible();

    const status = page.getByText(/Operational|Reachable, dependency degraded|Backend unreachable/);
    await expect(status).toBeVisible({ timeout: 15_000 });
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
