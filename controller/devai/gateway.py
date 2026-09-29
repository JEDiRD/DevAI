from dataclasses import dataclass
from typing import Protocol
import json
import urllib.error
import urllib.request


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayResult:
    content: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    provider_request_id: str | None = None


class GatewayClient(Protocol):
    def complete(
        self,
        model: str,
        prompt: str,
    ) -> str | GatewayResult:
        ...


class StaticGateway:

    def __init__(
        self,
        responses: dict[str, str | GatewayResult | Exception],
    ):
        self.responses = responses
        self.calls: list[str] = []

    def complete(
        self,
        model: str,
        prompt: str,
    ) -> str | GatewayResult:

        self.calls.append(model)
        response = self.responses.get(model)

        if isinstance(response, Exception):
            raise response

        if response is None:
            raise GatewayError(
                f"No response configured for {model}"
            )

        return response


class LiteLLMGateway:

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def complete(
        self,
        model: str,
        prompt: str,
    ) -> GatewayResult:

        payload = json.dumps({
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0,
        }).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=payload,
            headers={
                "Authorization":
                    f"Bearer {self.api_key}",
                "Content-Type":
                    "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                data = json.loads(response.read())

        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(
                "utf-8",
                errors="replace",
            )[:500]

            raise GatewayError(
                f"LiteLLM HTTP {exc.code}: {detail}"
            ) from exc

        except urllib.error.URLError as exc:
            raise GatewayError(
                f"LiteLLM connection failed: {exc.reason}"
            ) from exc

        if "error" in data:
            raise GatewayError(str(data["error"]))

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GatewayError(
                "LiteLLM returned invalid completion data"
            ) from exc

        usage = data.get("usage") or {}

        return GatewayResult(
            content=content,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get(
                "completion_tokens"
            ),
            provider_request_id=data.get("id"),
        )
