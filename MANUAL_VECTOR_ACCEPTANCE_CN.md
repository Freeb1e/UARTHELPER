# 单条 UART 向量验收说明

本目录为 FrodoKEM、Scloud+、ML-KEM 和 ML-DSA 的每个阶段提供可逐行抽取的 UART 命令与参考输出。规则统一为：命令文件第 N 行对应每个 `*_ref_*.txt` 的第 N 行，文件中没有空行或表头。文件均为 ASCII、LF 换行且末尾只有一个换行符；新生成的参考值使用大写十六进制，Scloud+ 既有命令中的十六进制为小写，板端解析及人工比较均不区分大小写。

## 文件对应关系

| 算法阶段 | 可直接发送的命令 | 同行参考输出 | 行数/参数 |
| --- | --- | --- | --- |
| Frodo KeyGen | `FRODOKEYGEN/keygen_commands_P.txt` | `pk_ref_P.txt`, `pkh_ref_P.txt` | 100；P=640/976/1344 |
| Frodo Encaps | `FRODOENCAPS/encaps_commands_P.txt` | `ct_ref_P.txt`, `ss_ref_P.txt` | 100；P=640/976/1344 |
| Frodo Decaps | `FRODODECAPS/decaps_commands_P.txt` | `ss_ref_P.txt`, `fail_mask_ref_P.txt` | 100；P=640/976/1344 |
| Scloud+ KeyGen | `SCLOUDKEYGEN/keygen_commands_P.txt` | `pk_ref_P.txt`, `sk_ref_P.txt` | 10；P=128/192/256/512 |
| Scloud+ Encaps | `SCLOUDENCAPS/encaps_commands_P.txt` | `ct_ref_P.txt`, `ss_ref_P.txt` | 10；P=128/192/256/512 |
| Scloud+ Decaps | `SCLOUDDECAPS/decaps_commands_P.txt` | `ss_ref_P.txt`, `fail_mask_ref_P.txt` | 11；P=128/192/256/512 |
| ML-KEM KeyGen | `MLKEMKEYGEN/keygen_commands_P.txt` | `pk_ref_P.txt`, `sk_ref_P.txt` | 3；P=512/768/1024 |
| ML-KEM Encaps | `MLKEMENCAPS/encaps_commands_P.txt` | `ct_ref_P.txt`, `ss_ref_P.txt` | 3；P=512/768/1024 |
| ML-KEM Decaps | `MLKEMDECAPS/decaps_commands_P.txt` | `ss_ref_P.txt` | 6；P=512/768/1024 |
| ML-DSA KeyGen | `MLDSAKEYGEN/keygen_commands_P.txt` | `pk_ref_P.txt`, `sk_ref_P.txt` | 3；P=44/65/87 |
| ML-DSA Sign | `MLDSASIGN/sign_uart_commands_P.txt` | `sig_ref_P.txt` | 3；P=44/65/87 |
| ML-DSA Verify | `MLDSAVERIFY/verify_uart_commands_P.txt` | `valid_ref_P.txt` | 6；P=44/65/87 |

`MLKEMENCAPS/encaps_inputs_P.txt`、`MLKEMDECAPS/decaps_inputs_P.txt`、`MLDSASIGN/sign_commands_P.txt` 和 `MLDSAVERIFY/verify_commands_P.txt` 是生成参考值所需的短源输入，不是完整板端 UART 命令。手工验收必须使用表中的最终命令文件。

Scloud+ Decaps 的第 1 至 10 行是合法 KAT，第 11 行是由 Count=0 派生的篡改密文。ML-KEM Decaps 和 ML-DSA Verify 每个源输入展开为相邻两行，顺序始终是合法、篡改，因此第 1/2、3/4、5/6 行分别为三组配对用例。ML-DSA Verify 的 `VALID` 参考值对应为 `1/0`。

## 手工抽取一条

例如验证 ML-KEM-512 Encaps 第 2 条：

```sh
sed -n '2p' UARTHELPER/MLKEMENCAPS/encaps_commands_512.txt
sed -n '2p' UARTHELPER/MLKEMENCAPS/ct_ref_512.txt
sed -n '2p' UARTHELPER/MLKEMENCAPS/ss_ref_512.txt
```

加载匹配阶段和参数集的固件后，以 115200 8N1 发送命令行并补一个换行，等待板端输出 `END`。将 `CT=` 与 `ct_ref`、`SS=` 与 `ss_ref` 逐字节比较。KeyGen、Sign、Verify 和带 `FAIL_MASK` 的阶段同理。长命令及长输出必须关闭串口工具的自动折行/截断；显示折行不能变成实际换行。

## 超长命令发送与日志保存

调试器固定使用以下两个文件，与启动命令所在的当前目录无关：

- 输入：`UARTHELPER/input.txt`
- 输出：`UARTHELPER/output.log`

直接编辑 `UARTHELPER/input.txt`，其中可以放测试向量，也可以放任意其他调试内容。脚本会逐字节原样发送整个文件，不抽取向量、不限制行数，也不会自动增加换行。目标协议需要回车或换行时，必须把它实际写入 `input.txt`。加载目标固件后运行：

```sh
python3 UARTHELPER/send_uart_file.py --port /dev/ttyUSB2
```

脚本按 115200 8N1 分块发送完整文件；板端返回会实时显示并以原始字节完整写入固定的 `UARTHELPER/output.log`。它不解析 `OK`、`ERROR` 或 `END`，收到第一个字节后连续 2 秒没有新数据即结束；第一个字节默认最多等待 300 秒。可用 `--baud-rate`、`--response-timeout`、`--idle-timeout` 修改串口和等待参数，或加 `--quiet` 只保存而不回显。每次运行都会覆盖上一次的 `output.log`。

## 重新生成与检查

生成器直接调用现有 KAT 解析器和仓库内未加速 Kyber/Dilithium 参考实现，不保存临时编译产物：

```sh
python3 UARTHELPER/generate_manual_vectors.py
python3 UARTHELPER/generate_manual_vectors.py --check
```

第一条命令更新派生的最终命令与参考文件。第二条命令重新计算全部结果并逐字节检查，不修改文件。Scloud+ 的既有 KAT 命令在两种模式下都只校验、不覆盖，防止官方向量输入被静默改变。运行需要 Python 3.10+、`cc`，以及 Python `hashlib` 的 SM3 支持；仅生成文件不需要串口或开发板。
