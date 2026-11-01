import { expect, test } from "@playwright/test";

for (const width of [390, 768, 1024, 1440]) {
  test(`landing layout and controls at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Find the flaw/ })).toBeVisible();
    await expect(page.locator("canvas.particle-background")).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    expect(await page.locator("canvas").evaluate(element => getComputedStyle(element).pointerEvents)).toBe("none");
    if (width === 390) {
      await page.getByLabel("Open navigation").click();
      await expect(page.getByRole("navigation", { name: "Mobile navigation" })).toBeVisible();
    }
    await page.getByRole("link", { name: /Start free/ }).last().click();
    await expect(page).toHaveURL(/\/register/);
    expect(errors).toEqual([]);
  });
}

test("particles move and respond to the mouse", async ({ page }) => {
  await page.addInitScript(() => { let seed=19; Math.random=()=>((seed=seed*16807%2147483647)/2147483647); });
  await page.setViewportSize({width:1440,height:900});
  await page.goto("/");
  const canvas=page.locator("canvas.particle-background");
  const first=await canvas.evaluate((element: HTMLCanvasElement)=>element.toDataURL());
  await page.waitForTimeout(500);
  const second=await canvas.evaluate((element: HTMLCanvasElement)=>element.toDataURL());
  expect(first).not.toBe(second);
  await page.mouse.move(720,450);
  await page.waitForTimeout(500);
  expect(await canvas.evaluate((element: HTMLCanvasElement)=>element.toDataURL())).not.toBe(second);
});

test("reduced motion keeps the background static", async ({ page }) => {
  await page.emulateMedia({reducedMotion:"reduce"});
  await page.goto("/");
  const canvas=page.locator("canvas.particle-background");
  await page.waitForTimeout(300);
  const first=await canvas.evaluate((element: HTMLCanvasElement)=>element.toDataURL());
  await page.mouse.move(100,100);
  await page.waitForTimeout(500);
  expect(await canvas.evaluate((element: HTMLCanvasElement)=>element.toDataURL())).toBe(first);
});

test("session service failure provides retry instead of redirecting", async ({ page }) => {
  await page.route("**/api/auth/me", route=>route.fulfill({status:503,json:{detail:"unavailable"}}));
  await page.goto("/app");
  await expect(page.getByRole("button",{name:"Retry connection"})).toBeVisible();
  await expect(page).toHaveURL(/\/app$/);
});
