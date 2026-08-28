import { lineTextAt } from './lines.mjs';

const EPHEMERAL_RM_TARGET_RE =
  /^(\.\/)?(node_modules|dist|build|out|coverage|target|\.next|\.nuxt|\.turbo|\.svelte-kit|\.cache|\.parcel-cache|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|venv|\.venv|\.eggs|[\w.-]+\.egg-info)\/?\*?$/i;

function rmTargetsRealData(line) {
  const m = /\brm\s+((?:-[a-zA-Z]+\s+)+)(.*)$/.exec(line);
  if (!m) return true;
  const targets = m[2]
    .split(/&&|\|\||[;|>&]/)[0]
    .split(/\s+/)
    .filter((t) => t && !t.startsWith('-'));
  if (!targets.length) return true;
  return !targets.every((t) => EPHEMERAL_RM_TARGET_RE.test(t.replace(/^["']|["']$/g, '')));
}

export function matchesShellSignal(sig, text) {
  if (!sig.refine) return sig.re.test(text);
  const g = new RegExp(sig.re.source, sig.re.flags.includes('g') ? sig.re.flags : sig.re.flags + 'g');
  for (const m of text.matchAll(g)) {
    if (m.index == null) continue;
    if (sig.refine(lineTextAt(text, m.index))) return true;
  }
  return false;
}

const SENSITIVE_PATH = String.raw`~/\.(?:ssh|aws|kube|gnupg|docker|config/gcloud)|/root/|/etc/(?:shadow|passwd|ssh)|id_[rd]sa|\.pem(?![.\w])|\.env(?![.\w])|credentials|\.npmrc|\.git-credentials|\bsecrets?\b|authorized_keys|\$HOME\b|/home(?:/[\w.-]+)?/?(?=[\s'"]|$)`;

export const DANGEROUS_SHELL = [
  { name: 'Pipe-to-shell installer (curl … | sh)', re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh\b/i, severity: 'CRITICAL' },
  { name: 'PowerShell download-and-run (iwr/curl … | iex)', re: /\b(iwr|curl|wget|invoke-webrequest|invoke-restmethod|irm)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)\b/i, severity: 'CRITICAL' },
  { name: 'Invoke-Expression of downloaded content', re: /\b(iex|invoke-expression)\b[^\n]{0,120}(downloadstring|net\.webclient|\(\s*(iwr|irm|invoke-)|\$\()/i, severity: 'CRITICAL' },
  { name: 'Reverse shell via /dev/tcp', re: /\/dev\/(tcp|udp)\//i, severity: 'CRITICAL' },
  { name: 'Base64 blob piped to a shell', re: /base64\s+(--?d(ecode)?)?\b[^\n|]{0,200}\|\s*(ba|z)?sh\b/i, severity: 'CRITICAL' },
  { name: 'curl/wget posts data to the network (exfiltration)', re: /\b(curl|wget|http|https|invoke-restmethod|irm)\b[^\n]{0,220}(--data(-raw|-binary|-urlencode)?|--form\b|--upload-file\b|(^|\s)-d\s|(^|\s)-F\s|(^|\s)-T\s|-Method\s+Post)/i, severity: 'HIGH' },
  { name: 'Command output piped into a network call', re: /\b(curl|wget|invoke-restmethod|invoke-webrequest|irm|iwr)\b[^\n]{0,220}(\$\(|`[^`\n]+`|<\()/i, severity: 'HIGH' },
  { name: 'Fetches from a raw IP address', re: /\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,220}https?:\/\/\d{1,3}(\.\d{1,3}){3}/i, severity: 'HIGH' },
  { name: 'Writes to shell profile / SSH keys / crontab', re: /(\.bashrc|\.zshrc|\.bash_profile|\.profile|authorized_keys|id_rsa\b|\bcrontab\b)/i, severity: 'HIGH' },

  {
    name: 'World-writable permissions on the filesystem root (chmod -R 777 /)',
    re: /\bchmod\b(?=[^\n;|&]*(?:-[a-zA-Z]*R|--recursive))(?=[^\n;|&]*(?:\b0?[0-7][0-7][2367]\b|a\+rwx|a=rwx|o\+w|ugo\+rwx))(?=[^\n;|&]*\s\/(?:\s|\*|$))/i,
    severity: 'CRITICAL',
  },
  {
    name: 'World-writable permissions on a credential or system path (chmod 777)',
    re: /\bchmod\b(?=[^\n;|&]*(?:\b0?[0-7][0-7][2367]\b|a\+rwx|a=rwx|o\+w|ugo\+rwx))(?=[^\n;|&]*(?:~(?:\s|$|\/\.)|\$HOME\b|\/etc\b|\/root\b|\/usr\b|\/var\b|\/boot\b|\.ssh\b|id_rsa\b|authorized_keys\b|\.aws\b|\.gnupg\b|\.kube\b))/i,
    severity: 'HIGH',
  },
  { name: 'Recursive force delete (rm -rf)', re: /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/i, severity: 'HIGH', refine: rmTargetsRealData },

  { name: 'Inline eval / exec of a string', re: /(?<![-.\w$>:`"'])(eval|exec)\s*[("`']/i, severity: 'HIGH' },
  { name: 'Pipes an env dump to the network', re: /\b(env|printenv|set)\b[^\n|]{0,80}\|[^\n]{0,80}(curl|wget|nc\b|http)/i, severity: 'HIGH' },
  { name: 'Disables TLS / cert verification', re: /(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|GIT_SSL_NO_VERIFY|--no-check-certificate|--insecure\b|verify\s*=\s*False)/i, severity: 'MEDIUM' },
  { name: 'python -c one-liner', re: /python[0-9.]*\s+-c\b/i, severity: 'MEDIUM' },
  { name: 'node -e one-liner', re: /\bnode\s+-e\b/i, severity: 'MEDIUM' },
  { name: 'Netcat / socket exfil', re: /\bnc\s+-[a-z]*\b|\bncat\b/i, severity: 'MEDIUM' },

  { name: 'Clears recorded shell history (anti-forensics)', re: /\bhistory\s+-c\b|\brm\b[^\n]{0,30}\.(bash|zsh|sh)_history\b|>\s*\S{0,30}\.(bash|zsh|sh)_history\b/i, severity: 'MEDIUM' },
  { name: 'Suppresses shell-history recording (anti-forensics)', re: /\bln\s+-s\S*\s+\/dev\/null\s+\S{0,40}\.(bash_|zsh_|sh_)?history\b|\bHISTFILE=\/dev\/null\b|\bunset\s+HISTFILE\b|\bexport\s+HIST(SIZE|FILESIZE)=0\b|\bset\s+\+o\s+history\b/i, severity: 'MEDIUM' },
  { name: 'Truncates a security / audit log (anti-forensics)', re: />\s*(\/var\/log\/(audit|secure|auth\.log|wtmp|btmp|lastlog|syslog|messages)|\/var\/(run|log)\/(wtmp|btmp|utmp))\b/i, severity: 'HIGH' },
  { name: 'Vacuums the systemd journal to erase records (anti-forensics)', re: /\bjournalctl\b[^\n]{0,40}--vacuum-(time|size)=/i, severity: 'MEDIUM' },
  { name: 'Wipes audit / security / login logs (anti-forensics)', re: /\b(rm|shred|unlink|truncate)\b[^\n]{0,60}(\/var\/log\/(audit|secure|auth\.log|wtmp|btmp|lastlog|syslog|messages|faillog|tallylog)|\/var\/(run|log)\/(wtmp|btmp|utmp))\b/i, severity: 'HIGH' },
  { name: 'Destroys managed infrastructure without confirmation (terraform destroy -auto-approve)', re: /\bterraform\b[^\n]{0,120}\bdestroy\b[^\n]{0,120}(-auto-approve|--auto-approve)/i, severity: 'HIGH' },
  { name: 'Force-deletes a cloud storage bucket (aws s3 rb --force)', re: /\b(aws\s+s3\s+rb|gsutil\s+(rm\s+-r|rb)|az\s+storage\s+(account|container)\s+delete)\b[^\n]{0,80}(--force|--yes|-f\b|\bs3:\/\/|\bgs:\/\/)/i, severity: 'HIGH' },
  { name: 'Force-pushes over a protected branch (rewrites shared history)', re: /\bgit\s+push\b[^\n]{0,80}(--force\b(?!-with-lease)|(?:^|\s)-f\b)[^\n]{0,60}\b(main|master|release|prod(uction)?)\b/i, severity: 'MEDIUM' },

  { name: 'Recursive force delete of the filesystem root (rm -rf /, --no-preserve-root)', re: /\brm\b(?=[^\n;|&]*(?:-[a-zA-Z]*r|--recursive))(?=[^\n;|&]*(?:-[a-zA-Z]*f|--force))(?=[^\n;|&]*(?:--no-preserve-root|\s\/(?:\s|\*|$)))/i, severity: 'CRITICAL' },
  { name: 'Fork bomb (process-exhaustion DoS)', re: /(:|\b[a-z_][a-z0-9_]*)\s*\(\s*\)\s*\{\s*\1\s*[^\n}]*\|\s*\1[^\n}]*&\s*\}\s*;\s*\1/i, severity: 'HIGH' },
  { name: 'Writes over a raw disk device (data destruction)', re: /\b(dd\b[^\n]{0,80}\bof=\/dev\/[sh]d|mkfs(\.\w+)?\s+[^\n]{0,40}\/dev\/|>\s*\/dev\/[sh]d[a-z])/i, severity: 'CRITICAL' },
  { name: 'Reads the system password-hash / sudo policy file', re: /\b(cat|less|more|head|tail|strings|xxd|od|grep|awk|sed|cp|scp|tar)\b[^\n]{0,80}\/etc\/(shadow|gshadow|sudoers(\.d)?)\b/i, severity: 'HIGH' },
  { name: 'Deletes a Kubernetes namespace / workload', re: /\bkubectl\b[^\n]{0,80}\bdelete\b[^\n]{0,80}\b(namespace|ns|deployment|statefulset|pvc|persistentvolumeclaim)\b/i, severity: 'MEDIUM' },
  { name: 'Drops a database / schema', re: /\bdrop\s+(database|schema|table)\b/i, severity: 'MEDIUM' },
  { name: 'Disables the audit / logging subsystem', re: /\b(systemctl|service)\s+(stop|disable|mask)\s+\S{0,20}(auditd|rsyslog|syslog|systemd-journald|journald)\b|\bauditctl\s+(-e\s*0|-D)\b|\bsetenforce\s+0\b|\bsystemctl\s+(stop|disable|mask)\s+firewalld\b/i, severity: 'HIGH' },

  { name: 'Locally decoded or decrypted blob piped to a shell', re: /\b(?:gpg|openssl\s+enc|xxd\s+-r|uudecode|zcat|gunzip|bunzip2|unxz)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/i, severity: 'CRITICAL' },
  { name: 'Container escape to the host (privileged / host mount / host namespace)', re: /\b(?:docker|podman|nerdctl)\s+(?:run|create|exec)\b[^\n]{0,200}?(?:--privileged\b|--pid[= ]host\b|--ipc[= ]host\b|--userns[= ]host\b|--security-opt[= ]\S{0,40}(?:seccomp[=:]unconfined|apparmor[=:]unconfined)|--cap-add[= ](?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b|-v\s+\/(?:\s|:)|--volume[= ]\/:|(?:-v|--volume)[= ]\s*\/var\/run\/docker\.sock)/i, severity: 'CRITICAL' },
  { name: 'Enters the host namespace from a container (nsenter / chroot onto a host mount)', re: /\bnsenter\b[^\n]{0,80}(?:-t\s*1\b|--target\s*1\b)|\bchroot\s+\/(?:host|mnt|proc\/1\/root)\b/i, severity: 'CRITICAL' },
  { name: 'Grants cluster-admin in Kubernetes', re: /\bkubectl\b[^\n]{0,120}\b(?:create|apply)\b[^\n]{0,120}\b(?:cluster)?rolebinding\b[^\n]{0,160}(?:--clusterrole[= ]\s*cluster-admin|cluster-admin)\b/i, severity: 'HIGH' },
  { name: 'Attaches an administrator policy to a cloud identity', re: /\baws\s+iam\s+(?:attach-(?:user|role|group)-policy|put-(?:user|role|group)-policy)\b[^\n]{0,160}(?:AdministratorAccess|PowerUserAccess|"?Action"?\s*:\s*"?\*)|\bgcloud\b[^\n]{0,120}add-iam-policy-binding\b[^\n]{0,160}roles\/(?:owner|editor|iam\.securityAdmin)\b|\baz\s+role\s+assignment\s+create\b[^\n]{0,160}--role\s+"?(?:Owner|Contributor|User Access Administrator)"?/i, severity: 'HIGH' },
  { name: 'Mints long-lived cloud credentials', re: /\baws\s+iam\s+create-access-key\b|\bgcloud\s+iam\s+service-accounts\s+keys\s+create\b|\baz\s+ad\s+sp\s+credential\s+reset\b/i, severity: 'MEDIUM' },
  { name: 'Grants itself passwordless sudo (writes the sudo policy)', re: /(?:>>?|tee\b[^\n]{0,40})\s*\/etc\/sudoers(?:\.d\/\S*)?\b|\bvisudo\b[^\n]{0,40}(?:-f|<<)|\becho\b[^\n]{0,120}NOPASSWD[^\n]{0,80}(?:>>?|tee)\s*\/etc\/sudoers/i, severity: 'HIGH' },
  { name: 'Installs a setuid / capability backdoor', re: /\bchmod\b[^\n]{0,60}(?:\bu\+s\b|\+s\b|\b[24][0-7]{3}\b)[^\n]{0,60}(?:\/bin\/|\/usr\/bin\/|\/tmp\/|\bbash\b|\bsh\b|\bdash\b)|\bsetcap\b[^\n]{0,60}cap_(?:setuid|setgid|sys_admin|dac_override|dac_read_search)\b/i, severity: 'HIGH' },
  { name: 'Grants an account administrator group membership', re: /\b(?:usermod|gpasswd)\b[^\n]{0,60}-a?[GM]\s*\S{0,20}\b(?:sudo|wheel|admin|root|docker|adm)\b|\b(?:useradd|adduser)\b[^\n]{0,80}-G\s*\S{0,30}\b(?:sudo|wheel|admin|root|docker)\b|\bnet\s+localgroup\b[^\n]{0,60}\badministrators?\b[^\n]{0,40}\/add\b|\bdscl\b[^\n]{0,80}-append\b[^\n]{0,60}\badmin\b/i, severity: 'MEDIUM' },
  { name: 'Preloads a shared library into every process (LD_PRELOAD)', re: /\b(?:LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES)\s*=\s*\S|>>?\s*\/etc\/ld\.so\.preload\b/i, severity: 'HIGH' },
  { name: 'Installs a scheduled or boot-time persistence unit', re: /\bsystemd-run\b[^\n]{0,80}--on-(?:boot|calendar|active|unit)|>>?\s*\/etc\/(?:systemd\/system|cron\.(?:d|daily|hourly)|init\.d)\/\S|\bschtasks\b[^\n]{0,80}\/create\b|\blaunchctl\s+(?:load|bootstrap)\b|\b(?:echo|printf)\b[^\n]{0,120}\|\s*at\s+(?:now|\+|\d)/i, severity: 'MEDIUM' },
  { name: 'Opens a reverse tunnel to a remote host', re: /\bssh\b[^\n]{0,80}\s-\w*R\s*\d{1,5}:[^\n\s]{1,60}|\b(?:ngrok|cloudflared|localtunnel|frpc)\b[^\n]{0,60}\b(?:tcp|http|tunnel)\b/i, severity: 'HIGH' },
  { name: 'Encodes command output into DNS lookups (exfiltration channel)', re: /(?:^|[\n;&|(]\s*)(?:dig|nslookup|drill|host)\s+[^\n]{0,120}(?:\$\(|`|\$\{)[^\n]{0,80}\.[a-z]{2,}/i, severity: 'HIGH' },
  { name: 'Copies credentials or home directories off the machine over ssh', re: new RegExp(String.raw`\b(?:scp|rsync)\b(?=[^\n]{0,200}\s\S{0,40}@[\w.-]+:)(?=[^\n]{0,200}(?:${SENSITIVE_PATH}))` + String.raw`|\btar\b(?=[^\n]{0,160}\|\s*ssh\b)(?=[^\n]{0,160}(?:${SENSITIVE_PATH}))`, 'i'), severity: 'HIGH' },
  { name: 'Flushes the host firewall', re: /\b(?:iptables|ip6tables|nft)\b[^\n]{0,60}(?:-F\b|--flush\b|flush ruleset)|\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\s+\S+\s+state\s+off\b/i, severity: 'MEDIUM' },
  { name: 'Kills the audit / EDR agent (anti-forensics)', re: /\b(?:pkill|killall|kill)\b[^\n]{0,40}\b(?:auditd|osqueryd?|falcon-sensor|falconctl|wazuh|ossec|filebeat|splunkd|sysmon|crowdstrike|carbonblack|cbagent)\b|\bSet-MpPreference\b[^\n]{0,60}-Disable\w*\s+\$?true/i, severity: 'HIGH' },
  { name: 'Downloads and executes through a signed system binary (LOLBin)', re: /\bcertutil\b[^\n]{0,80}-urlcache\b|\bbitsadmin\b[^\n]{0,80}\/transfer\b|\bmshta\b\s+https?:\/\/|\bregsvr32\b[^\n]{0,60}\/i:\s*https?:\/\/|\brundll32\b[^\n]{0,60}\b(?:url\.dll|javascript:)|\bwmic\b[^\n]{0,60}\bprocess\s+call\s+create\b|\bmsiexec\b[^\n]{0,40}\/i\s+https?:\/\//i, severity: 'CRITICAL' },
  { name: 'PowerShell runs a base64-encoded command', re: /\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|ec|enc|encoded|encodedcommand)\b/i, severity: 'CRITICAL' },
  { name: 'Interpreter opens a raw socket (reverse shell)', re: /\b(?:perl|ruby|php|python[0-9.]*|node)\b[^\n]{0,40}-(?:e|r|c)\b[^\n]{0,200}\b(?:fsockopen|socket\s*\(|Socket::|SOCK_STREAM|net\.connect|createConnection)\b/i, severity: 'CRITICAL' },
  { name: 'Netcat listener or command-execution flag', re: /\bn?c(?:at)?\b[^\n]{0,40}\s-\w*[ec]\s+\S{0,30}(?:sh|bash|cmd|powershell)\b|\bn?c(?:at)?\b[^\n]{0,20}\s-\w*l\w*\s*(?:-\w+\s*)*\d{2,5}\b/i, severity: 'HIGH' },
];
