import { expect, test } from "@playwright/test";

// UI contract fixtures only. Real database isolation is tested by integration_db.py.
const job = {
  id: "10000000-0000-4000-8000-000000000001", name: "demo-firmware.zip", provider: "none",
  state: "complete", created_at: 1793500000, source_files: 1,
  source: { type: "github", repository: "demo/firmware", branch: "main", commit_sha: "abc123def456" },
  report: { scan_status: "PARTIAL", source_files: 1, analyzer_status: { Semgrep: {status:"failed",error:"unavailable"} } },
  findings: [{ id:"finding-1", file:"src/main.c", line:3, severity:"warning", message:"Dereference of null pointer",
    rule_id:"nullPointer", source_tool:"Cppcheck", source_tools:["Cppcheck"], classification:"SUPPORTED_CWE",
    cwe:{id:"CWE-476",name:"NULL Pointer Dereference"}, evidence:"read_value(NULL)", mapping_confidence:"high" }],
  checks: { build:"not_available", tests:"not_available", sanitizers:"not_available", security:"not_run", verification_outcome:"not_verified" },
};

test.beforeEach(async ({page})=>{
  await page.route("**/api/**", route=>{
    const url=new URL(route.request().url());
    if(url.pathname==="/api/auth/me")return route.fulfill({json:{id:"demo",email:"demo@example.com"}});
    if(url.pathname==="/api/jobs")return route.fulfill({json:[job]});
    if(url.pathname.endsWith("/files"))return route.fulfill({json:{files:["src/main.c"]}});
    if(url.pathname.endsWith("/source"))return route.fulfill({json:{file:"src/main.c",original:"int read_value(int *p) { return *p; }",line:3}});
    if(url.pathname.endsWith("/repair-status"))return route.fulfill({json:{job_busy:false,operation:{},checks:job.checks,attempt_count:0,max_attempts:3,attempt_history:[]}});
    if(url.pathname==="/api/providers")return route.fulfill({json:{providers:{ollama:{configured:false},groq:{configured:false}}}});
    if(url.pathname===`/api/jobs/${job.id}`)return route.fulfill({json:job});
    return route.fulfill({status:404,json:{detail:"No saved proposal"}});
  });
});

for(const width of [390,768,1024,1440]){
  test(`workspace routes at ${width}px`,async({page})=>{
    await page.setViewportSize({width,height:900});
    const errors:string[]=[];page.on("pageerror",error=>errors.push(error.message));
    const routes=["/app","/app/projects","/app/scans","/app/reports",`/app/analysis/${job.id}`,"/app/settings","/login","/register"];
    if(!process.env.PATCH8_SKIP_LEGACY)routes.push("/firmware");
    for(const route of routes){
      const response=await page.goto(route);
      expect(response?.ok(),route).toBe(true);
      await expect(page.locator("h1").first()).toBeVisible();
      await page.waitForTimeout(150);
      expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),route).toBe(true);
      if(route==="/app"){
        await expect(page.getByText("Partial",{exact:true})).toBeVisible();
        await expect(page.getByText("Not assessed",{exact:true}).first()).toBeVisible();
      }
      if(route==="/app/projects"&&width===390)await page.screenshot({path:"test-results/projects-mobile.png",fullPage:true});
    }
    expect(errors).toEqual([]);
  });
}

test("non-JSON upload failure leaves a retryable control",async({page})=>{
  await page.route("**/api/jobs",route=>route.fulfill({status:502,body:"upstream unavailable",contentType:"text/plain"}));
  await page.goto("/app/projects");
  await page.locator('input[type="file"]').first().setInputFiles({name:"main.c",mimeType:"text/plain",buffer:Buffer.from("int main(void){return 0;}")});
  await page.getByRole("button",{name:"Start scan"}).click();
  await expect(page.getByRole("button",{name:"Start scan"})).toBeEnabled();
  await expect(page.getByRole("status")).toContainText(/failed|unreadable|502/i);
});
