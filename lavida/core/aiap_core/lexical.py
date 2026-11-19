"""Offline ranking over a single authorized snapshot."""
import re
import sqlite3
import unicodedata

HAN = r"\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U000323af"
RUNS = re.compile(fr"[{HAN}]+|[^\W_{HAN}]+")
METHOD = "scoped-offline-bm25"


def terms(text):
    for match in RUNS.finditer(unicodedata.normalize("NFKC", text).casefold()):
        word = match.group()
        if len(word) > 1 and re.fullmatch(fr"[{HAN}]+", word):
            yield from (word[i:i + 2] for i in range(len(word) - 1))
        else:
            yield word


def rank(records, query, limit):
    needle = query.casefold()
    exact = [i for i, record in enumerate(records) if needle in record["content"].casefold()]
    tokens = list(dict.fromkeys(terms(query)))
    ordered = exact
    method = METHOD
    if tokens and len(exact) <= limit and len(exact) < len(records):
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE VIRTUAL TABLE corpus USING fts5(tokens)")
            db.executemany("INSERT INTO corpus(rowid,tokens) VALUES (?,?)",
                           ((i, " ".join(terms(m["content"]))) for i, m in enumerate(records)))
            expression = " OR ".join(f'"{token}"' for token in tokens)
            rows = db.execute("SELECT rowid FROM corpus WHERE corpus MATCH ? ORDER BY rank,rowid LIMIT ?",
                              (expression, limit + 1 + len(exact)))
            seen = set(exact)
            ordered = exact + [i for (i,) in rows if i not in seen]
        except sqlite3.OperationalError as exc:
            if "no such module: fts5" not in str(exc).lower():
                raise
            method = "scoped-literal-substring"
        finally:
            db.close()
    return [records[i] for i in ordered[:limit]], len(ordered) > limit, method
