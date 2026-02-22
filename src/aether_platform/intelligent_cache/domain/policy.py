class BypassPolicy:
    """
    Domain logic for identifying notable URIs and determining scanning priority.

    This policy no longer supports automatic bypass for security reasons,
    but it identifies known registries for metrics aggregation.
    """

    _NOTABLE_DOMAIN_MAP = {
        "pypi.org": "python",
        "files.pythonhosted.org": "python",
        "registry.npmjs.org": "node",
        "repo.maven.apache.org": "java",
        "github.com": "github",
        "objects.githubusercontent.com": "github",
        "get.docker.com": "docker",
        "registry-1.docker.io": "docker",
        "quay.io": "docker",
        "gcr.io": "docker",
        "ghcr.io": "docker",
        "registry.k8s.io": "docker",
    }

    def _get_matched_domain(self, uri: str) -> str | None:
        """Internal helper to find the first matching notable domain in a URI."""
        for domain in self._NOTABLE_DOMAIN_MAP:
            if domain in uri:
                return domain
        return None

    def __init__(self, notable_domains: dict[str, str] = None):
        """
        Initializes the policy.

        Args:
            notable_domains: Optional override for the notable domain mapping.
        """
        self.notable_domains = notable_domains or self._NOTABLE_DOMAIN_MAP

    def get_notable_type(self, uri: str) -> str | None:
        """
        Retrieves the category (e.g., 'docker') of the URI if it's notable.

        Args:
            uri: The full request URI.

        Returns:
            The category string or None.
        """
        domain = self._get_matched_domain(uri)
        return self.notable_domains.get(domain) if domain else None

    def should_bypass(self, uri: str) -> bool:
        """
        Policy decision on whether to skip scanning.

        NOTE: This now ALWAYS returns False as automatic bypass is disabled
        per the latest security requirements. Only cache hits allow skipping.
        """
        return False
