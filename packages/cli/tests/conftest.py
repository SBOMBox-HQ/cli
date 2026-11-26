"""Keep CLI tests offline: no update check at interpreter exit, no usage telemetry."""
import os

os.environ["SBOMBOX_NO_UPDATE_CHECK"] = "1"
os.environ["SBOMBOX_NO_TELEMETRY"] = "1"
