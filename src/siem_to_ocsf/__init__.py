"""siem-to-ocsf: normalise heterogeneous SIEM/vendor alerts into OCSF Detection Findings."""

from siem_to_ocsf.ocsf import OCSF_VERSION

__all__ = ["OCSF_VERSION", "__version__"]
__version__ = "0.1.0"
