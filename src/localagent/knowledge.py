"""Small local SQLite/FTS5 knowledge base used by the agent."""

from __future__ import annotations

from pathlib import Path
import sqlite3

from .policy import FilesystemPolicy


class KnowledgeBase:
    """Store text documents in SQLite and search them through FTS5 with a LIKE fallback."""

    def __init__(self, path, chunk_chars=1800, policy: FilesystemPolicy | None = None):
        """Open or create a knowledge database at ``path``."""
        self.policy = policy
        candidate = Path(path)
        self.path = policy.authorize(candidate, "write", actor="runtime") if policy else candidate
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.chunk_chars = chunk_chars
        self.db = sqlite3.connect(self.path)
        self.db.execute('CREATE TABLE IF NOT EXISTS docs(path TEXT PRIMARY KEY, text TEXT, mtime REAL)')
        self.db.execute('CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(path UNINDEXED, text)')
        self.db.commit()

    def add(self, path, content=None):
        """Index a file or supplied text, replacing any previous entry for ``path``."""
        logical_path = Path(path)
        read_path = self.policy.authorize(logical_path, "read") if self.policy else logical_path
        text = content if content is not None else read_path.read_text(encoding='utf-8', errors='replace')
        stored_path = str(logical_path)
        self.db.execute('DELETE FROM docs_fts WHERE path=?', (stored_path,))
        self.db.execute(
            'INSERT OR REPLACE INTO docs(path,text,mtime) VALUES(?,?,?)',
            (stored_path, text, read_path.stat().st_mtime if read_path.exists() else 0),
        )
        for i in range(0, len(text), self.chunk_chars):
            self.db.execute('INSERT INTO docs_fts(path,text) VALUES(?,?)', (stored_path, text[i:i + self.chunk_chars]))
        self.db.commit()

    def search(self, q, limit=8):
        """Search indexed text and return path/snippet dictionaries."""
        try:
            rows = self.db.execute(
                'SELECT path,snippet(docs_fts,1,"","", "…", 24) FROM docs_fts WHERE docs_fts MATCH ? LIMIT ?',
                (q, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = self.db.execute(
                'SELECT path,substr(text,1,500) FROM docs WHERE text LIKE ? LIMIT ?',
                ('%' + q + '%', limit),
            ).fetchall()
        return [{'path': r[0], 'snippet': r[1]} for r in rows]

    def read(self, path):
        """Return the full indexed text for an exact stored path, or ``None``."""
        return self.db.execute('SELECT text FROM docs WHERE path=?', (path,)).fetchone()
