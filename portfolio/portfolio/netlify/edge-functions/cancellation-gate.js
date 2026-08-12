const COOKIE_NAME = "case_cancellation_auth";
const ENV_VAR = "PROTECTED_PAGE_PASSWORD_CANCELLATION";

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function gateHtml(showError) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Same-Day Loan Cancellation — Natália Amaral</title>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght,WONK@0,9..144,100..900,0;0,9..144,100..900,1;1,9..144,100..900,0;1,9..144,100..900,1&family=DM+Sans:ital,wght@0,300;0,400;0,500;1,300&display=swap" rel="stylesheet"/>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #F5F3EE; color: #111110; font-family: 'DM Sans', system-ui, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
  .gate-card { background: #FAFAF7; border-radius: 1.5rem; padding: 2.5rem; max-width: 380px; width: 100%; text-align: center; box-shadow: 0 1px 24px rgba(17,17,16,0.08); }
  .gate-title { font-family: 'Fraunces', Georgia, serif; font-weight: 900; font-style: italic; font-size: 1.4rem; color: #111110; margin-bottom: 0.5rem; }
  .gate-sub { font-size: 0.85rem; color: #7A7873; font-weight: 300; margin-bottom: 1.5rem; }
  .gate-input { width: 100%; padding: 0.75rem 1rem; border-radius: 0.75rem; border: 1px solid #E5E2DB; font-family: 'DM Sans', sans-serif; font-size: 0.9rem; margin-bottom: 0.75rem; outline: none; }
  .gate-input:focus { border-color: #1A5C3A; }
  .gate-btn { width: 100%; background: #1A5C3A; color: #fff; border: none; padding: 0.75rem 1rem; border-radius: 0.75rem; font-family: 'DM Sans', sans-serif; font-size: 0.9rem; font-weight: 500; cursor: pointer; }
  .gate-btn:hover { background: #2E7D52; }
  .gate-error { font-size: 0.8rem; color: #B85C38; margin-top: 0.75rem; ${showError ? "" : "display: none;"} }
  .gate-back { display: inline-block; margin-top: 1.25rem; font-size: 0.8rem; color: #7A7873; text-decoration: none; }
</style>
</head>
<body>
  <div class="gate-card">
    <div class="gate-title">This case isn't public yet</div>
    <p class="gate-sub">Enter the password to view this case study.</p>
    <form method="POST">
      <input type="password" name="password" class="gate-input" placeholder="Password" autofocus/>
      <button type="submit" class="gate-btn">Unlock</button>
    </form>
    <p class="gate-error">Incorrect password — try again.</p>
    <a href="/" class="gate-back">← Back to projects</a>
  </div>
</body>
</html>`;
}

export default async (request, context) => {
  const password = Netlify.env.get(ENV_VAR);
  const url = new URL(request.url);

  if (!password) {
    return new Response(
      `This page is not yet configured. The site owner needs to set the ${ENV_VAR} environment variable.`,
      { status: 503, headers: { "content-type": "text/plain" } }
    );
  }

  const expectedHash = await sha256(password);

  // Logout
  if (url.searchParams.get("logout") === "1") {
    const response = Response.redirect(url.origin + url.pathname, 302);
    response.headers.append(
      "Set-Cookie",
      `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
    );
    return response;
  }

  // Valid session cookie -> serve the real page, injecting a logout link
  const cookies = request.headers.get("cookie") || "";
  const match = cookies.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (match && match[1] === expectedHash) {
    const response = await context.next();
    const html = await response.text();
    const injected = html.replace(
      "<body>",
      `<body><a href="?logout=1" style="position:fixed;bottom:1rem;right:1rem;z-index:998;font-size:0.75rem;color:#7A7873;background:#FAFAF7;padding:0.4rem 0.8rem;border-radius:2rem;text-decoration:none;box-shadow:0 1px 12px rgba(17,17,16,0.08);">Log out</a>`
    );
    return new Response(injected, response);
  }

  // Password submitted
  if (request.method === "POST") {
    const form = await request.formData();
    const submitted = form.get("password") || "";
    const submittedHash = await sha256(String(submitted));
    if (submittedHash === expectedHash) {
      const response = Response.redirect(url.origin + url.pathname, 302);
      response.headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${expectedHash}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`
      );
      return response;
    }
    return new Response(gateHtml(true), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  return new Response(gateHtml(false), {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};

export const config = { path: "/case-cancellation.html" };
