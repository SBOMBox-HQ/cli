"""Keep CLI tests offline: no update check at interpreter exit."""
import os

os.environ["SBOMBOX_NO_UPDATE_CHECK"] = "1"
