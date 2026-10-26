"""Synthetic example: flag a review marker without returning its contents."""
from leakguard_core.plugins import Finding

API_VERSION = 1


class ReviewMarker:
    def detect(self, text, path, part):
        for number, line in enumerate(text.splitlines(), 1):
            if 'SYNTHETIC_REVIEW_MARKER' in line:
                yield Finding('example-review-marker', number, 'review')


def create_plugin(options):
    return ReviewMarker()
