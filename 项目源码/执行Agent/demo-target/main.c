/* demo-vuln-app 1.0 —— A1 流水线冒烟测试用的极简目标程序
 * 三个面（对应三轴判定）：
 *   1) 功能面： --hello          → 打印 DEMO_OK v1.0, exit 0
 *   2) 泄露面： --read <path>    → 打印 SECRET_READ=<首行> 或 SECRET_READ=denied
 *   3) 漏洞面： <任意长参数>      → 16 字节栈缓冲无边界拷贝（CWE-120，仅此一个根因）
 * 诚实边界：这不是真实软件，只用于验证流水线；不计入赛题漏洞分。
 */
#include <stdio.h>
#include <string.h>

static void read_secret(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("SECRET_READ=denied\n");
        return;
    }
    char line[128];
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        printf("SECRET_READ=%s\n", line);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--hello") == 0) {
        printf("DEMO_OK v1.0\n");
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "--read") == 0) {
        read_secret(argv[2]);
        return 0;
    }
    if (argc >= 2) {
        char buf[16];
        strcpy(buf, argv[1]);   /* 故意保留：无边界检查 */
        printf("ECHO=%s\n", buf);
        return 0;
    }
    printf("DEMO_OK v1.0\n");
    return 0;
}
