"""Tarvia SOC triage workflow. Run from the repository root: python -m src.main"""

from .database.sync import AlertFeed


def main() -> None:
    with AlertFeed() as feed:
        while (alert := feed.next_alert()) is not None:
            feed.store(alert)


if __name__ == "__main__":
    main()
