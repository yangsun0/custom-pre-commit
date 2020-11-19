import re

from detect_secrets.plugins.base import classproperty
from detect_secrets.plugins.base import RegexBasedDetector


class CustomSecreteDetector(RegexBasedDetector):
    """Scans for custom secretes."""
    secret_type = 'Custom Secrete'

    @classproperty
    def disable_flag_text(self):
        return 'no-custom-scan'

    denylist = [
        re.compile(regexp, 
          re.IGNORECASE)
        for regexp in (
            r'.*apps\.googleusercontent\.com',
        )
    ]
