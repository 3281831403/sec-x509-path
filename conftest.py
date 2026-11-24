"""让仓库根目录可直接导入 x509 包，不依赖安装步骤。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))