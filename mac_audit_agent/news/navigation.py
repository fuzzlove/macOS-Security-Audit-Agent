from __future__ import annotations

import random

from .models import NewsArticle


class NewsNavigator:
    def __init__(self, chooser: random.Random | None = None) -> None:
        self.articles: list[NewsArticle] = []
        self.current_article_id: str | None = None
        self._chooser = chooser or random.SystemRandom()

    @property
    def index(self) -> int:
        return next((index for index, article in enumerate(self.articles) if article.article_id == self.current_article_id), -1)

    @property
    def current(self) -> NewsArticle | None:
        position = self.index
        return self.articles[position] if position >= 0 else None

    @property
    def can_newer(self) -> bool: return self.index > 0

    @property
    def can_older(self) -> bool: return 0 <= self.index < len(self.articles) - 1

    def replace(self, articles: list[NewsArticle], preserve: bool = True, auto_advance_latest: bool = False) -> NewsArticle | None:
        previous_id = self.current_article_id
        was_latest = self.index == 0 and self.index >= 0
        self.articles = list(articles)
        ids = {article.article_id for article in articles}
        if preserve and previous_id in ids and not (was_latest and auto_advance_latest):
            self.current_article_id = previous_id
        else:
            self.current_article_id = articles[0].article_id if articles else None
        return self.current

    def latest(self) -> NewsArticle | None:
        if self.articles: self.current_article_id = self.articles[0].article_id
        return self.current

    def older(self) -> NewsArticle | None:
        if self.can_older: self.current_article_id = self.articles[self.index + 1].article_id
        return self.current

    def newer(self) -> NewsArticle | None:
        if self.can_newer: self.current_article_id = self.articles[self.index - 1].article_id
        return self.current

    def surprise(self) -> NewsArticle | None:
        if not self.articles: return None
        candidates = [article for article in self.articles if len(self.articles) == 1 or article.article_id != self.current_article_id]
        self.current_article_id = self._chooser.choice(candidates).article_id
        return self.current
