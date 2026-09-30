from dataclasses import dataclass
from decimal import Decimal

from .db import connect


class PricingNotConfigured(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelPrice:
    pricing_key: str
    version: int
    input_per_million_usd: Decimal
    output_per_million_usd: Decimal

    def __post_init__(self):
        if any(not isinstance(value,Decimal) or not value.is_finite() or value<0
                for value in (self.input_per_million_usd,self.output_per_million_usd)):
            raise PricingNotConfigured('INVALID_PRICE_SNAPSHOT')


def get_active_price(
    pricing_key: str,
) -> ModelPrice:

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    version,
                    input_per_million_usd,
                    output_per_million_usd
                FROM model_pricing
                WHERE pricing_key = %s
                  AND active = TRUE
                """,
                (pricing_key,),
            )

            row = cur.fetchone()

    if row is None:
        raise PricingNotConfigured(
            f"No active pricing for {pricing_key}"
        )

    return ModelPrice(
        pricing_key=pricing_key,
        version=row[0],
        input_per_million_usd=row[1],
        output_per_million_usd=row[2],
    )


def calculate_cost(
    price: ModelPrice,
    prompt_tokens: int,
    completion_tokens: int,
) -> Decimal:

    million = Decimal("1000000")
    if any(type(value) is not int or value < 0 for value in (prompt_tokens,completion_tokens)):
        raise ValueError('INVALID_TOKEN_USAGE')

    return (
        Decimal(prompt_tokens)
        * price.input_per_million_usd
        / million
        +
        Decimal(completion_tokens)
        * price.output_per_million_usd
        / million
    )
