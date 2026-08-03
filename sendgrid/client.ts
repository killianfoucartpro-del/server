import axios, { type AxiosRequestConfig } from "axios";
import { HttpsProxyAgent } from "https-proxy-agent";

const SENDGRID_API = "https://api.sendgrid.com/v3";

export type SendGridCheck = {
  status: "valid" | "invalid" | "free" | "network_error" | "failed";
  creditLimit: number | null;
  usedCredits: number | null;
  resetFrequency: string | null;
  fromEmail: string | null;
  domains: string[];
  providerStatus: number | null;
  errorMessage: string | null;
};

function requestConfig(apiKey: string, proxy?: string | null): AxiosRequestConfig {
  const config: AxiosRequestConfig = {
    headers: { Authorization: `Bearer ${apiKey}` },
    timeout: 15_000,
    validateStatus: () => true,
  };

  if (proxy) {
    config.httpsAgent = new HttpsProxyAgent(`http://${proxy}`);
    config.proxy = false;
  }

  return config;
}

function providerError(data: unknown) {
  if (!data || typeof data !== "object") return "Réponse fournisseur non reconnue";
  const errors = (data as { errors?: Array<{ message?: string }> }).errors;
  return errors?.[0]?.message || "Requête refusée par SendGrid";
}

async function loadSenderContext(apiKey: string, proxy?: string | null) {
  const config = requestConfig(apiKey, proxy);
  const domainResponse = await axios.get(`${SENDGRID_API}/whitelabel/domains`, config);
  if (domainResponse.status < 200 || domainResponse.status >= 300 || !Array.isArray(domainResponse.data)) {
    return { domains: [] as string[], fromEmail: null as string | null };
  }

  const domains = domainResponse.data
    .map((item: { domain?: unknown }) => (typeof item.domain === "string" ? item.domain : ""))
    .filter(Boolean)
    .slice(0, 10);
  const aliases = new Map<string, number>();

  for (const domain of domains) {
    try {
      const messageResponse = await axios.get(`${SENDGRID_API}/messages`, {
        ...config,
        params: { limit: 10, query: `from_email LIKE '%${domain.replace(/'/g, "")}'` },
      });
      const messages = messageResponse.data?.messages;
      if (!Array.isArray(messages)) continue;
      for (const message of messages) {
        const from = typeof message?.from_email === "string" ? message.from_email.toLowerCase() : "";
        if (from) aliases.set(from, (aliases.get(from) || 0) + 1);
      }
    } catch {
      // Message Activity access is optional. Domain data remains useful.
    }
  }

  const rankedAliases = Array.from(aliases.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([email]) => email);

  return {
    domains,
    fromEmail: rankedAliases[0] || (domains[0] ? `@${domains[0]}` : null),
  };
}

export async function checkSendGridKey(apiKey: string, proxy?: string | null): Promise<SendGridCheck> {
  try {
    const response = await axios.get(`${SENDGRID_API}/user/credits`, requestConfig(apiKey, proxy));
    if (response.status === 401 || response.status === 403) {
      return {
        status: "invalid",
        creditLimit: null,
        usedCredits: null,
        resetFrequency: null,
        fromEmail: null,
        domains: [],
        providerStatus: response.status,
        errorMessage: providerError(response.data),
      };
    }
    if (response.status < 200 || response.status >= 300) {
      return {
        status: "network_error",
        creditLimit: null,
        usedCredits: null,
        resetFrequency: null,
        fromEmail: null,
        domains: [],
        providerStatus: response.status,
        errorMessage: providerError(response.data),
      };
    }

    const creditLimit = Number(response.data?.total || 0);
    const usedCredits = Number(response.data?.used || 0);
    const resetFrequency = String(response.data?.reset_frequency || "N/A");
    const senderContext = await loadSenderContext(apiKey, proxy);

    return {
      status: creditLimit === 0 && usedCredits === 0 ? "free" : "valid",
      creditLimit,
      usedCredits,
      resetFrequency,
      fromEmail: senderContext.fromEmail,
      domains: senderContext.domains,
      providerStatus: response.status,
      errorMessage: null,
    };
  } catch (error) {
    const message = axios.isAxiosError(error)
      ? error.code === "ECONNABORTED"
        ? "Délai réseau dépassé"
        : error.message
      : "Erreur réseau inattendue";
    return {
      status: "network_error",
      creditLimit: null,
      usedCredits: null,
      resetFrequency: null,
      fromEmail: null,
      domains: [],
      providerStatus: null,
      errorMessage: message,
    };
  }
}

export async function sendTestEmail(input: {
  apiKey: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  proxy?: string | null;
}) {
  try {
    const response = await axios.post(
      `${SENDGRID_API}/mail/send`,
      {
        personalizations: [{ to: [{ email: input.to }] }],
        from: { email: input.from },
        subject: input.subject,
        content: [{ type: "text/plain", value: input.body }],
      },
      requestConfig(input.apiKey, input.proxy),
    );
    return {
      success: response.status === 202,
      providerStatus: response.status,
      errorMessage: response.status === 202 ? null : providerError(response.data),
    };
  } catch (error) {
    return {
      success: false,
      providerStatus: null,
      errorMessage: axios.isAxiosError(error) ? error.message : "Erreur d’envoi inattendue",
    };
  }
}
