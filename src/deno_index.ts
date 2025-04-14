import { serve } from "https://deno.land/std@0.202.0/http/server.ts";

const TARGET_URL = "https://grok.com";
const ORIGIN_DOMAIN = "grok.com";

const AUTH_USERNAME = Deno.env.get("AUTH_USERNAME");
const AUTH_PASSWORD = Deno.env.get("AUTH_PASSWORD");
const COOKIE = Deno.env.get("cookie");

// 存储cookie刷新状态
let lastCookieRefreshTime = 0;
let isRefreshing = false;
const REFRESH_INTERVAL = 7200000; // 2小时
const MAX_RETRIES = 3;

// 自动刷新cookie
async function refreshCookie(): Promise<string> {
  if (isRefreshing) return COOKIE || '';
  isRefreshing = true;
  
  try {
    console.log('Attempting to refresh cookie...');
    const response = await fetch(`${TARGET_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Cookie': COOKIE || '',
        'Content-Type': 'application/json'
      }
    });
    
    if (response.ok) {
      const cookies = response.headers.get('set-cookie');
      if (cookies) {
        console.log('Cookie refreshed successfully');
        await Deno.env.set('cookie', cookies);
        lastCookieRefreshTime = Date.now();
        return cookies;
      } else {
        console.warn('No cookies in refresh response');
      }
    } else {
      console.error(`Cookie refresh failed with status: ${response.status}`);
      // 尝试读取错误响应内容
      try {
        const errorText = await response.text();
        console.error('Error response:', errorText);
      } catch (e) {
        console.error('Could not read error response');
      }
    }
  } catch (error) {
    console.error('Failed to refresh cookie:', error);
  } finally {
    isRefreshing = false;
  }
  
  return COOKIE || '';
}

// 验证cookie是否有效
function validateCookie(cookie: string): boolean {
  if (!cookie) return false;
  const hasCfClearance = cookie.includes("cf_clearance=");
  const hasSso = cookie.includes("sso=");
  return hasCfClearance && hasSso;
}

// 从cookie中提取cf_clearance和sso值
function extractCookies(cookie: string): { cfClearance: string; sso: string } {
  const cookies = cookie.split(';').map(c => c.trim());
  const cfClearance = cookies.find(c => c.startsWith('cf_clearance='))?.split('=')[1] || '';
  const sso = cookies.find(c => c.startsWith('sso='))?.split('=')[1] || '';
  return { cfClearance, sso };
}

// 检查cookie是否即将过期（完全禁用过期检测）
function isCookieExpiringSoon(cfClearance: string): boolean {
  try {
    const cookieParts = cfClearance.split('-');
    if (cookieParts.length >= 2) {
      const expiryTimestamp = parseInt(cookieParts[1]);
      const currentTime = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = expiryTimestamp - currentTime;
      
      // 仅在后台尝试刷新cookie，但不影响请求处理
      if (timeUntilExpiry < 3600 && (Date.now() - lastCookieRefreshTime) > REFRESH_INTERVAL) {
        // 异步刷新cookie，不阻塞当前请求
        setTimeout(() => refreshCookie().catch(console.error), 0);
      }
    }
  } catch (error) {
    console.error('Error checking cookie expiry:', error);
  }
  // 始终返回false，完全禁用过期检测，避免401错误
  return false;
}

// 验证Basic Auth
function isValidAuth(authHeader: string): boolean {
  try {
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = atob(base64Credentials);
    const [username, password] = credentials.split(":");
    return username === AUTH_USERNAME && password === AUTH_PASSWORD;
  } catch {
    return false;
  }
}

// 处理WebSocket连接
async function handleWebSocket(req: Request): Promise<Response> {
  const { socket: clientWs, response } = Deno.upgradeWebSocket(req);
  const url = new URL(req.url);
  const targetUrl = `wss://grok.com${url.pathname}${url.search}`;

  console.log('Target URL:', targetUrl);

  const pendingMessages: string[] = [];
  const targetWs = new WebSocket(targetUrl);

  targetWs.onopen = () => {
    console.log('Connected to grok');
    pendingMessages.forEach(msg => targetWs.send(msg));
    pendingMessages.length = 0;
  };

  clientWs.onmessage = (event) => {
    console.log('Client message received');
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.send(event.data);
    } else {
      pendingMessages.push(event.data);
    }
  };

  targetWs.onmessage = (event) => {
    console.log('message received');
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.send(event.data);
    }
  };

  clientWs.onclose = (event) => {
    console.log('Client connection closed');
    if (targetWs.readyState === WebSocket.OPEN) {
      targetWs.close(1000, event.reason);
    }
  };

  targetWs.onclose = (event) => {
    console.log('connection closed');
    if (clientWs.readyState === WebSocket.OPEN) {
      clientWs.close(event.code, event.reason);
    }
  };

  targetWs.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  return response;
}

// 主处理函数
const handler = async (req: Request): Promise<Response> => {
  // Basic Auth 验证
  const authHeader = req.headers.get("Authorization");
  if (AUTH_USERNAME && AUTH_PASSWORD && (!authHeader || !isValidAuth(authHeader))) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="Proxy Authentication Required"',
      },
    });
  }

  // 处理WebSocket请求
  if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
    return handleWebSocket(req);
  }

  const url = new URL(req.url);
  const targetUrl = new URL(url.pathname + url.search, TARGET_URL);
  const cookie = COOKIE || req.headers.get('cookie') || '';

  // Cookie验证
  if (!validateCookie(cookie)) {
    return new Response("Unauthorized: Invalid cookie", { status: 401 });
  }

  // 检查cookie是否即将过期
  const { cfClearance } = extractCookies(cookie);
  // 完全禁用cookie过期检查，即使cookie即将过期也继续处理请求
  // 在后台异步刷新cookie
  if (cfClearance) {
    setTimeout(() => refreshCookie().catch(console.error), 0);
  }
  // 不再返回401错误，继续处理请求

  // 构造代理请求
  const headers = new Headers(req.headers);
  headers.set("Host", targetUrl.host);
  headers.delete("Referer");
  headers.delete("Cookie");
  headers.delete("Authorization");
  headers.set("cookie", cookie);

  try {
    // 解析和验证请求体
    let requestBody = null;
    if (req.method !== 'GET') {
      try {
        const contentType = req.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
          const bodyText = await req.text();
          console.log('Request body:', bodyText);
          // 验证JSON格式
          JSON.parse(bodyText);
          requestBody = bodyText;
        } else {
          requestBody = req.body;
        }
      } catch (bodyError) {
        console.error('Request body parsing error:', bodyError);
        return new Response(JSON.stringify({
          error: 'Invalid request body',
          message: 'Failed to parse request body as JSON'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    console.log('Proxying request to:', targetUrl.toString());
    console.log('Request method:', req.method);
    console.log('Request headers:', Object.fromEntries(headers.entries()));

    const proxyResponse = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: requestBody,
      redirect: "manual",
    });

    // 处理响应头
    const responseHeaders = new Headers(proxyResponse.headers);
    responseHeaders.delete("Content-Length");
    const location = responseHeaders.get("Location");
    if (location) {
      responseHeaders.set("Location", location.replace(TARGET_URL, `https://${ORIGIN_DOMAIN}`));
    }

    // 处理无响应体状态码
    if ([204, 205, 304].includes(proxyResponse.status)) {
      return new Response(null, { status: proxyResponse.status, headers: responseHeaders });
    }

    // 创建流式转换器
    const transformStream = new TransformStream({
      transform: async (chunk, controller) => {
        const contentType = responseHeaders.get("Content-Type") || "";
        if (contentType.startsWith("text/") || contentType.includes("json")) {
          let text = new TextDecoder("utf-8", { stream: true }).decode(chunk);
          controller.enqueue(
            new TextEncoder().encode(text.replaceAll(TARGET_URL, ORIGIN_DOMAIN))
          );
        } else {
          controller.enqueue(chunk);
        }
      }
    });

    const readableStream = proxyResponse.body?.pipeThrough(transformStream);

    return new Response(readableStream, {
      status: proxyResponse.status,
      headers: responseHeaders,
    });
    // 检查并记录响应状态
    if (!proxyResponse.ok) {
      console.error('Proxy response error:', {
        status: proxyResponse.status,
        statusText: proxyResponse.statusText,
        headers: Object.fromEntries(proxyResponse.headers.entries())
      });
      const errorBody = await proxyResponse.text();
      console.error('Error response body:', errorBody);
    }

  } catch (error) {
    console.error('Proxy Error:', error);
    console.error('Error details:', {
      url: targetUrl.toString(),
      method: req.method,
      headers: Object.fromEntries(headers.entries()),
      error: error.stack || error.message
    });
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message,
      details: error.stack,
      url: targetUrl.toString()
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

serve(handler, { port: 8000 });
console.log('Grok proxy server running on http://localhost:8000');
