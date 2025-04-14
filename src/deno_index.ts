import { serve } from "https://deno.land/std@0.202.0/http/server.ts";

const TARGET_URL = "https://grok.com";
const ORIGIN_DOMAIN = "grok.com"; // 注意：此处应仅为域名，不含协议

const AUTH_USERNAME = Deno.env.get("AUTH_USERNAME");
const AUTH_PASSWORD = Deno.env.get("AUTH_PASSWORD");

const COOKIE = Deno.env.get("cookie");

// 验证函数
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

  if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
    return handleWebSocket(req);
  }

  const url = new URL(req.url);
  const targetUrl = new URL(url.pathname + url.search, TARGET_URL);

  // 构造代理请求
  const headers = new Headers(req.headers);
  headers.set("Host", targetUrl.host);
  headers.delete("Referer");
  headers.delete("Cookie");
  headers.delete("Authorization"); // 删除验证头，不转发到目标服务器
  headers.set("cookie", COOKIE || '');

  try {
    console.log('Proxying request to:', targetUrl.toString());
    console.log('Request method:', req.method);
    
    const proxyResponse = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: req.body,
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

          //   if(contentType.includes("json"))
          //   {
          //       if(text.includes("streamingImageGenerationResponse"))
          //       {
          //           text = text.replaceAll('users/','https://assets.grok.com/users/');
          //       }
          //   }

          controller.enqueue(
            new TextEncoder().encode(text.replaceAll(TARGET_URL, ORIGIN_DOMAIN))
          );
        } else {
          controller.enqueue(chunk);
        }
      }
    });

    // 创建可读流
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
