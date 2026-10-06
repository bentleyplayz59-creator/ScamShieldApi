// routes/api/analyze.ts
//
// ScamShield Analyzer API
// BentleyPlayz Project
//
// Endpoint:
// POST /api/analyze
//
// Accepts:
// - multipart/form-data
//   - text: suspicious message/content
//   - context: optional additional context
//   - attachments: one or more image files
//
// Also supports legacy JSON requests:
// {
//   "text": "...",
//   "context": "...",
//   "image": "data:image/png;base64,..."
// }

import { Handlers } from "$fresh/server.ts";

const ALLOWED_ORIGINS = new Set([
  "https://scamshield.bentleyplayz.com",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
]);

const MAX_REQUEST_BYTES = 10 * 1024 * 1024;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_IMAGES = 5;
const MAX_TEXT_LENGTH = 20_000;
const MAX_CONTEXT_LENGTH = 10_000;

const ALLOWED_IMAGE_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
]);

/*
 * openrouter/free is preferred because OpenRouter can select an
 * available free model that supports the capabilities we request.
 *
 * The explicit Llama vision model is included as a known free
 * vision-capable fallback.
 */
const FREE_VISION_MODELS = [
  "openrouter/free",
  "meta-llama/llama-3.2-11b-vision-instruct:free",
];

const FREE_TEXT_MODELS = [
  "openrouter/free",
  "meta-llama/llama-3.1-8b-instruct:free",
  "google/gemma-3-4b-it:free",
  "qwen/qwen3-4b:free",
];

const SYSTEM_PROMPT = `
You are ScamShield, an anti-scam safety assistant created by BentleyPlayz.

Your job is to analyze suspicious messages, emails, texts, invoices, screenshots,
popups, social-media messages, phone-call descriptions, and other potentially
fraudulent content.

Your goal is to help ordinary people recognize scams and make safer decisions.

IMPORTANT SAFETY RULES:

1. Never claim that something is 100% definitely a scam or 100% definitely safe.
2. Give a risk level:
   - low
   - suspicious
   - high
3. Explain the important warning signs in plain English.
4. Be especially alert for:
   - urgency
   - threats
   - pressure
   - secrecy
   - impersonation
   - requests for passwords
   - verification codes
   - Social Security numbers
   - bank information
   - credit-card information
   - gift cards
   - cryptocurrency
   - wire transfers
   - remote computer access
   - unexpected refunds
   - fake prizes
   - fake government officials
   - fake police
   - fake banks
   - fake technical support
   - fake Microsoft/Apple/Google support
   - fake family emergencies
   - account-closure threats
   - suspicious links
   - suspicious domains
   - suspicious phone numbers
   - suspicious email addresses
   - instructions not to hang up
   - instructions to stay on the phone
   - instructions not to tell anyone
5. Treat urgency as a warning sign, not a reason to hurry.
6. Tell the user not to click suspicious links, call numbers supplied by
   suspicious messages, send money, buy gift cards, provide passwords/codes,
   or give remote computer access merely to "see if it is real."
7. Encourage independent verification using a trusted official website,
   official phone number, bank card, statement, or another independently
   obtained source.
8. Encourage the user to ask someone they trust if they are unsure.
9. If sensitive information appears in an uploaded image, do not repeat
   unnecessary sensitive information back to the user.
10. If the evidence is incomplete, explicitly say that the analysis is limited.
11. Never tell the user to continue interacting with a suspicious sender.
12. The central ScamShield rule is:
   "When in doubt, hang up."

Return ONLY valid JSON.

Use exactly this structure:

{
  "risk": "low" | "suspicious" | "high",
  "confidence": number,
  "summary": string,
  "warning_signs": string[],
  "recommended_actions": string[],
  "independent_verification": string[],
  "sensitive_information_requested": string[],
  "reasoning": string,
  "disclaimer": string
}

The confidence number must be between 0 and 100.

Keep the response understandable to a non-technical person.
`.trim();

interface AnalysisResult {
  risk: "low" | "suspicious" | "high";
  confidence: number;
  summary: string;
  warning_signs: string[];
  recommended_actions: string[];
  independent_verification: string[];
  sensitive_information_requested: string[];
  reasoning: string;
  disclaimer: string;
}

function jsonResponse(
  body: unknown,
  status = 200,
  origin?: string,
): Response {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  }

  return new Response(JSON.stringify(body), {
    status,
    headers,
  });
}

function getCorsHeaders(origin: string | null): Headers {
  const headers = new Headers({
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  });

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
  }

  return headers;
}

function cleanText(value: unknown, maxLength: number): string {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .replace(/\u0000/g, "")
    .trim()
    .slice(0, maxLength);
}

function isValidImageDataUrl(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }

  return /^data:image\/(?:png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=\s]+$/i
    .test(value);
}

function normalizeRisk(value: unknown): AnalysisResult["risk"] {
  const risk = String(value ?? "").toLowerCase().trim();

  if (risk === "high") {
    return "high";
  }

  if (risk === "suspicious" || risk === "medium") {
    return "suspicious";
  }

  return "low";
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((item) => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 20);
}

function normalizeResult(value: unknown): AnalysisResult {
  const input =
    value && typeof value === "object"
      ? value as Record<string, unknown>
      : {};

  const confidenceRaw = Number(input.confidence);

  const confidence = Number.isFinite(confidenceRaw)
    ? Math.max(0, Math.min(100, Math.round(confidenceRaw)))
    : 50;

  return {
    risk: normalizeRisk(input.risk),

    confidence,

    summary:
      typeof input.summary === "string" && input.summary.trim()
        ? input.summary.trim().slice(0, 2_000)
        : "ScamShield could not produce a detailed summary.",

    warning_signs: normalizeStringArray(input.warning_signs),

    recommended_actions: normalizeStringArray(
      input.recommended_actions,
    ),

    independent_verification: normalizeStringArray(
      input.independent_verification,
    ),

    sensitive_information_requested: normalizeStringArray(
      input.sensitive_information_requested,
    ),

    reasoning:
      typeof input.reasoning === "string"
        ? input.reasoning.trim().slice(0, 4_000)
        : "",

    disclaimer:
      typeof input.disclaimer === "string" && input.disclaimer.trim()
        ? input.disclaimer.trim().slice(0, 2_000)
        : "ScamShield provides an AI-assisted warning assessment, not a guarantee. When in doubt, hang up.",
  };
}

function extractJson(text: string): unknown {
  const cleaned = text
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    // Continue below and attempt to locate a JSON object.
  }

  const firstBrace = cleaned.indexOf("{");
  const lastBrace = cleaned.lastIndexOf("}");

  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const possibleJson = cleaned.slice(firstBrace, lastBrace + 1);

    try {
      return JSON.parse(possibleJson);
    } catch {
      return null;
    }
  }

  return null;
}

function fileToDataUrl(
  file: File,
  bytes: Uint8Array,
): string {
  let binary = "";

  const chunkSize = 32_768;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(
      i,
      Math.min(i + chunkSize, bytes.length),
    );

    binary += String.fromCharCode(...chunk);
  }

  const base64 = btoa(binary);

  return `data:${file.type};base64,${base64}`;
}

async function parseMultipartRequest(req: Request): Promise<{
  text: string;
  context: string;
  images: string[];
}> {
  const form = await req.formData();

  const text = cleanText(
    form.get("text"),
    MAX_TEXT_LENGTH,
  );

  const context = cleanText(
    form.get("context"),
    MAX_CONTEXT_LENGTH,
  );

  const files: File[] = [];

  for (const [key, value] of form.entries()) {
    if (
      (key === "attachments" || key === "file" || key === "image") &&
      value instanceof File
    ) {
      files.push(value);
    }
  }

  if (files.length > MAX_IMAGES) {
    throw new Error(`You can upload up to ${MAX_IMAGES} images.`);
  }

  const images: string[] = [];

  for (const file of files) {
    if (!ALLOWED_IMAGE_TYPES.has(file.type.toLowerCase())) {
      throw new Error(
        `Unsupported image type: ${file.type || "unknown"}.`,
      );
    }

    if (file.size > MAX_IMAGE_BYTES) {
      throw new Error(
        `Each image must be 8 MB or smaller.`,
      );
    }

    const bytes = new Uint8Array(await file.arrayBuffer());

    images.push(fileToDataUrl(file, bytes));
  }

  return {
    text,
    context,
    images,
  };
}

async function parseJsonRequest(req: Request): Promise<{
  text: string;
  context: string;
  images: string[];
}> {
  const body = await req.json();

  if (!body || typeof body !== "object") {
    throw new Error("Invalid JSON request.");
  }

  const input = body as Record<string, unknown>;

  const text = cleanText(
    input.text,
    MAX_TEXT_LENGTH,
  );

  const context = cleanText(
    input.context,
    MAX_CONTEXT_LENGTH,
  );

  const images: string[] = [];

  if (isValidImageDataUrl(input.image)) {
    images.push(input.image);
  }

  if (Array.isArray(input.images)) {
    for (const image of input.images) {
      if (isValidImageDataUrl(image)) {
        images.push(image);
      }
    }
  }

  if (images.length > MAX_IMAGES) {
    throw new Error(`You can upload up to ${MAX_IMAGES} images.`);
  }

  return {
    text,
    context,
    images,
  };
}

async function parseRequest(req: Request): Promise<{
  text: string;
  context: string;
  images: string[];
}> {
  const contentType = req.headers.get("content-type") ?? "";

  if (contentType.toLowerCase().includes("multipart/form-data")) {
    return await parseMultipartRequest(req);
  }

  if (contentType.toLowerCase().includes("application/json")) {
    return await parseJsonRequest(req);
  }

  throw new Error(
    "Use multipart/form-data or application/json.",
  );
}

function buildUserText(
  text: string,
  context: string,
  imageCount: number,
): string {
  const parts: string[] = [];

  parts.push(
    "Analyze the following material for possible scam or fraud indicators.",
  );

  if (text) {
    parts.push(
      `\nSUSPICIOUS CONTENT:\n${text}`,
    );
  }

  if (context) {
    parts.push(
      `\nUSER CONTEXT:\n${context}`,
    );
  }

  if (imageCount > 0) {
    parts.push(
      `\nThe user uploaded ${imageCount} image(s). Carefully inspect the image content, including visible text, URLs, phone numbers, names, logos, payment instructions, warnings, and other scam indicators.`,
    );
  }

  parts.push(
    "\nReturn the required JSON structure and nothing else.",
  );

  return parts.join("\n");
}

async function callOpenRouter(
  apiKey: string,
  text: string,
  context: string,
  images: string[],
): Promise<{
  result: AnalysisResult;
  model: string;
}> {
  const hasImages = images.length > 0;

  const models = hasImages
    ? FREE_VISION_MODELS
    : FREE_TEXT_MODELS;

  const content: Array<
    | { type: "text"; text: string }
    | {
      type: "image_url";
      image_url: {
        url: string;
      };
    }
  > = [];

  content.push({
    type: "text",
    text: buildUserText(
      text,
      context,
      images.length,
    ),
  });

  for (const image of images) {
    content.push({
      type: "image_url",
      image_url: {
        url: image,
      },
    });
  }

  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, 60_000);

  try {
    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://scamshield.bentleyplayz.com/",
          "X-Title": "ScamShield",
        },
        body: JSON.stringify({
          models,
          messages: [
            {
              role: "system",
              content: SYSTEM_PROMPT,
            },
            {
              role: "user",
              content,
            },
          ],
          temperature: 0.1,
          max_tokens: 1_800,
        }),
      },
    );

    if (!response.ok) {
      const errorText = await response.text();

      console.error(
        "OpenRouter request failed:",
        response.status,
        errorText.slice(0, 1_000),
      );

      if (response.status === 429) {
        throw new Error(
          "ScamShield is temporarily busy. Please try again in a moment.",
        );
      }

      if (response.status >= 500) {
        throw new Error(
          "The scam analysis service is temporarily unavailable.",
        );
      }

      throw new Error(
        "The scam analysis service rejected the request.",
      );
    }

    const data = await response.json();

    const model =
      typeof data?.model === "string"
        ? data.model
        : "unknown";

    const output =
      data?.choices?.[0]?.message?.content;

    if (typeof output !== "string" || !output.trim()) {
      console.error(
        "OpenRouter returned no usable content.",
      );

      throw new Error(
        "The analysis service returned an empty response.",
      );
    }

    const parsed = extractJson(output);

    if (!parsed) {
      console.error(
        "OpenRouter returned non-JSON output:",
        output.slice(0, 2_000),
      );

      throw new Error(
        "The analysis service returned an invalid response.",
      );
    }

    return {
      result: normalizeResult(parsed),
      model,
    };
  } catch (error) {
    if (
      error instanceof DOMException &&
      error.name === "AbortError"
    ) {
      throw new Error(
        "The scam analysis took too long. Please try again.",
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function validateInput(
  text: string,
  context: string,
  images: string[],
): string | null {
  if (!text && !context && images.length === 0) {
    return "Please provide a suspicious message, context, or image to analyze.";
  }

  if (text.length > MAX_TEXT_LENGTH) {
    return "The suspicious content is too long.";
  }

  if (context.length > MAX_CONTEXT_LENGTH) {
    return "The context is too long.";
  }

  if (images.length > MAX_IMAGES) {
    return `You can upload up to ${MAX_IMAGES} images.`;
  }

  return null;
}

export const handler: Handlers = {
  async OPTIONS(req) {
    const origin = req.headers.get("origin");

    if (
      origin &&
      !ALLOWED_ORIGINS.has(origin)
    ) {
      return new Response(null, {
        status: 403,
      });
    }

    return new Response(null, {
      status: 204,
      headers: getCorsHeaders(origin),
    });
  },

  async POST(req) {
    const origin = req.headers.get("origin");

    if (
      origin &&
      !ALLOWED_ORIGINS.has(origin)
    ) {
      return jsonResponse(
        {
          success: false,
          error: "Origin not allowed.",
        },
        403,
      );
    }

    const contentLengthHeader =
      req.headers.get("content-length");

    if (contentLengthHeader) {
      const contentLength = Number(
        contentLengthHeader,
      );

      if (
        Number.isFinite(contentLength) &&
        contentLength > MAX_REQUEST_BYTES
      ) {
        return jsonResponse(
          {
            success: false,
            error: "Request is too large. Please use smaller images.",
          },
          413,
          origin ?? undefined,
        );
      }
    }

    try {
      const apiKey =
        Deno.env.get("OPENROUTER_API");

      if (!apiKey) {
        console.error(
          "OPENROUTER_API secret is not configured.",
        );

        return jsonResponse(
          {
            success: false,
            error: "ScamShield analysis is not configured yet.",
          },
          500,
          origin ?? undefined,
        );
      }

      const {
        text,
        context,
        images,
      } = await parseRequest(req);

      const validationError = validateInput(
        text,
        context,
        images,
      );

      if (validationError) {
        return jsonResponse(
          {
            success: false,
            error: validationError,
          },
          400,
          origin ?? undefined,
        );
      }

      const {
        result,
        model,
      } = await callOpenRouter(
        apiKey,
        text,
        context,
        images,
      );

      return jsonResponse(
        {
          success: true,
          result,
          model,
          disclaimer:
            "ScamShield provides an AI-assisted warning assessment, not a guarantee. When in doubt, hang up.",
        },
        200,
        origin ?? undefined,
      );
    } catch (error) {
      console.error(
        "ScamShield API error:",
        error instanceof Error
          ? error.message
          : error,
      );

      const message =
        error instanceof Error
          ? error.message
          : "Unable to analyze the content.";

      return jsonResponse(
        {
          success: false,
          error: message,
        },
        500,
        origin ?? undefined,
      );
    }
  },

  async GET(_req) {
    return jsonResponse(
      {
        success: true,
        service: "ScamShield API",
        status: "online",
        endpoint: "/api/analyze",
        message:
          "ScamShield API is running. Send POST requests to /api/analyze.",
      },
      200,
    );
  },
};