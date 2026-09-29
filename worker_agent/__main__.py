"""Run the Windows Worker without passing credentials on the command line."""

import argparse
import logging
from pathlib import Path

from .agent import AgentConfig, WorkerAgent


def main() -> None:
    parser = argparse.ArgumentParser(description="Dev AI Windows Worker")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    agent = WorkerAgent(AgentConfig.load(args.config))
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
