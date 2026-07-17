#!/usr/bin/env python3
"""Cliente LLM plugavel (Anthropic / OpenAI / Google Gemini) via REST.

Design:
- Interface unica `generate(system, user) -> str`; trocar de provedor e uma
  linha no config.yaml (`llm.provider`), sem tocar no resto do codigo.
- Chaves lidas exclusivamente do .env / variaveis de ambiente (nunca do YAML).
- requests com timeout em toda chamada; retry curto com backoff para 429/5xx.
- Erro seguro: mensagens nunca incluem a chave; corpo de resposta truncado.
"""

import time

import requests

TIMEOUT = 120          # segundos por requisicao
RETRIES = 2            # tentativas extras em 429/5xx

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4o",
    "gemini": "gemini-flash-latest",
}


class LLMError(RuntimeError):
    """Erro de configuracao ou chamada ao provedor LLM."""


class LLMClient:
    """Base: retry/backoff e contrato generate(). Subclasses implementam _call."""

    provider = ""
    key_env = ""

    def __init__(self, model: str, api_key: str, max_tokens: int = 8000,
                 temperature: float = 0.2, timeout: int = TIMEOUT):
        if not api_key:
            raise LLMError(
                f"Chave do provedor '{self.provider}' ausente. "
                f"Defina {self.key_env} no .env (veja .env.example)."
            )
        self.model = model
        self._key = api_key
        self.max_tokens = int(max_tokens)
        self.temperature = float(temperature)
        self.timeout = int(timeout)

    def generate(self, system: str, user: str) -> str:
        last: Exception | None = None
        for attempt in range(RETRIES + 1):
            try:
                return self._call(system, user)
            except requests.HTTPError as e:
                last = e
                status = e.response.status_code if e.response is not None else 0
                if status in (429, 500, 502, 503, 529) and attempt < RETRIES:
                    time.sleep(2 ** (attempt + 1))
                    continue
                break
            except requests.RequestException as e:
                last = e
                if attempt < RETRIES:
                    time.sleep(2 ** (attempt + 1))
                    continue
        if isinstance(last, requests.HTTPError) and last.response is not None:
            detail = f" HTTP {last.response.status_code}: {last.response.text[:300]}"
        elif last is not None:
            # Falha de rede (sem resposta): expor o tipo ajuda o diagnostico
            # (ReadTimeout = modelo demorou; SSLError/ProxyError = rede local)
            detail = f" Erro de rede: {type(last).__name__}"
        else:
            detail = ""
        raise LLMError(f"Falha na chamada ao provedor '{self.provider}'.{detail}") from last

    def _call(self, system: str, user: str) -> str:  # pragma: no cover - abstrato
        raise NotImplementedError

    def list_models(self) -> list[str]:  # pragma: no cover - abstrato
        raise NotImplementedError


class AnthropicClient(LLMClient):
    provider = "anthropic"
    key_env = "ANTHROPIC_API_KEY"

    def _call(self, system: str, user: str) -> str:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self._key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": self.max_tokens,
                  "temperature": self.temperature, "system": system,
                  "messages": [{"role": "user", "content": user}]},
            timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return "".join(b.get("text", "") for b in data.get("content", []))

    def list_models(self) -> list[str]:
        r = requests.get("https://api.anthropic.com/v1/models",
                         headers={"x-api-key": self._key,
                                  "anthropic-version": "2023-06-01"},
                         timeout=self.timeout)
        r.raise_for_status()
        return sorted(m.get("id", "") for m in r.json().get("data", []))


class OpenAIClient(LLMClient):
    provider = "openai"
    key_env = "OPENAI_API_KEY"

    def _call(self, system: str, user: str) -> str:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._key}",
                     "content-type": "application/json"},
            json={"model": self.model, "max_tokens": self.max_tokens,
                  "temperature": self.temperature,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]},
            timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        choices = data.get("choices") or []
        return (choices[0].get("message") or {}).get("content", "") if choices else ""

    def list_models(self) -> list[str]:
        r = requests.get("https://api.openai.com/v1/models",
                         headers={"Authorization": f"Bearer {self._key}"},
                         timeout=self.timeout)
        r.raise_for_status()
        return sorted(m.get("id", "") for m in r.json().get("data", []))


class GeminiClient(LLMClient):
    provider = "gemini"
    key_env = "GEMINI_API_KEY"

    def _call(self, system: str, user: str) -> str:
        # Chave via header (nao via query string) para nao vazar em logs de proxy.
        r = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent",
            headers={"x-goog-api-key": self._key, "content-type": "application/json"},
            json={"systemInstruction": {"parts": [{"text": system}]},
                  "contents": [{"role": "user", "parts": [{"text": user}]}],
                  "generationConfig": {"maxOutputTokens": self.max_tokens,
                                       "temperature": self.temperature}},
            timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        cands = data.get("candidates") or []
        parts = ((cands[0].get("content") or {}).get("parts") or []) if cands else []
        return "".join(p.get("text", "") for p in parts)

    def list_models(self) -> list[str]:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                         headers={"x-goog-api-key": self._key},
                         timeout=self.timeout)
        r.raise_for_status()
        out = []
        for m in r.json().get("models", []):
            if "generateContent" in (m.get("supportedGenerationMethods") or []):
                out.append(m.get("name", "").removeprefix("models/"))
        return sorted(out)


_REGISTRY: dict[str, type[LLMClient]] = {
    "anthropic": AnthropicClient,
    "claude": AnthropicClient,
    "openai": OpenAIClient,
    "gpt": OpenAIClient,
    "gemini": GeminiClient,
    "google": GeminiClient,
}


def create_client(cfg: dict, env: dict) -> LLMClient:
    """Factory: instancia o cliente do provedor configurado no config.yaml."""
    llm = cfg.get("llm") or {}
    provider = str(llm.get("provider", "")).lower().strip()
    cls = _REGISTRY.get(provider)
    if cls is None:
        raise LLMError(
            f"Provedor LLM '{provider or '(vazio)'}' nao suportado. "
            "Use no config.yaml: anthropic | openai | gemini"
        )
    model = str(llm.get("model") or DEFAULT_MODELS[cls.provider])
    return cls(model=model, api_key=env.get(cls.key_env, ""),
               max_tokens=llm.get("max_tokens", 8000),
               temperature=llm.get("temperature", 0.2),
               timeout=llm.get("timeout", TIMEOUT))
