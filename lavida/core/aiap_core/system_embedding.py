"""Optional system-owned embedding models."""
import math
import platform
import re
import sys
import threading
import time

from .contracts import require
from .semantic import ProviderUnavailable, VectorRanker


class SystemEmbedding(VectorRanker):
    provider = 'system'

    def __init__(self, language, scopes):
        super().__init__(scopes)
        require(isinstance(language, str) and re.fullmatch(r'[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}', language),
                'E_EMBED_CONFIG')
        self.language = language
        self.model_key = language
        self.model = self.dimensions = None
        self.native = None
        self.error = None
        self.inference_lock = threading.Lock()
        if sys.platform != 'darwin':
            self.error = 'E_SYSTEM_EMBED_UNSUPPORTED'
            return
        if int(platform.mac_ver()[0].split('.')[0] or 0) < 14:
            self.error = 'E_SYSTEM_EMBED_UNSUPPORTED'
            return
        try:
            from NaturalLanguage import NLContextualEmbedding
        except ImportError:
            self.error = 'E_SYSTEM_EMBED_BRIDGE_MISSING'
            return
        self.native = NLContextualEmbedding.contextualEmbeddingWithLanguage_(language)
        if self.native is None:
            self.error = 'E_SYSTEM_EMBED_LANGUAGE'
            return
        self.dimensions = self.native.dimension()
        self.model = f'apple-natural-language:{self.native.modelIdentifier()}@{self.native.revision()}'
        self.loaded = False

    def setup(self):
        reason = self.error
        if self.native is not None and not self.native.hasAvailableAssets():
            reason = 'E_SYSTEM_EMBED_ASSETS_REQUIRED'
        result = {'provider': self.provider, 'language': self.language,
                  'state': reason or 'ready', 'model': self.model}
        if reason == 'E_SYSTEM_EMBED_ASSETS_REQUIRED':
            result['action'] = f'aiap embedding download --language {self.language}'
        elif reason == 'E_SYSTEM_EMBED_BRIDGE_MISSING':
            result['action'] = 'Install aiap-core-service[system-embedding] in the AIAP Python environment.'
        return result

    def download(self, timeout=120):
        state = self.setup()['state']
        if state == 'ready':
            return self.setup()
        if state != 'E_SYSTEM_EMBED_ASSETS_REQUIRED':
            return self.setup()
        done = threading.Event()
        self.native.requestEmbeddingAssetsWithCompletionHandler_(lambda *_: done.set())
        done.wait(timeout)
        return self.setup()

    def embed(self, texts, deadline):
        reason = self.setup()['state']
        if reason != 'ready':
            raise ProviderUnavailable(reason)
        try:
            with self.inference_lock:
                if not self.loaded:
                    self.loaded, _ = self.native.loadWithError_(None)
                    if not self.loaded:
                        raise ProviderUnavailable('E_SYSTEM_EMBED_UNAVAILABLE')
                vectors = []
                for text in texts:
                    if time.monotonic() >= deadline:
                        raise ProviderUnavailable('E_EMBED_TIMEOUT')
                    vectors.append(self._vector(text))
                return vectors
        except ProviderUnavailable:
            raise
        except Exception:
            raise ProviderUnavailable('E_SYSTEM_EMBED_UNAVAILABLE') from None

    def _vector(self, text):
        result, _ = self.native.embeddingResultForString_language_error_(text, self.language, None)
        if result is None:
            raise ProviderUnavailable('E_SYSTEM_EMBED_INPUT')
        # Bounded pooling over the model's token window. Ignore special tokens with empty ranges.
        total = [0.0] * self.dimensions

        def collect(vector, span, _stop):
            if span.length:
                for index, value in enumerate(vector):
                    total[index] += value
            return False

        result.enumerateTokenVectorsInRange_usingBlock_((0, len(text.encode('utf-16-le')) // 2), collect)
        norm = math.hypot(*total)
        if not norm or not math.isfinite(norm):
            return total
        return [value / norm for value in total]
