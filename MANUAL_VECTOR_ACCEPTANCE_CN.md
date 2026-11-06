# 单条 UART 向量验收说明

当前 [HWDISPLAY](../e203_hbirdv2/scripts/HWDISPLAY/README.md) 提供与本目录命令匹配的 UART 固件和 JTAG 加载入口，支持 FrodoKEM-SHAKE-640/976/1344、Scloud+-SM3-128/192/256 的 KeyGen、Encaps、Decaps。[SIMDISPLAY](../e203_hbirdv2/scripts/SIMDISPLAY/README.md) 使用相同解析器和 PACE 算法内核，在真实 E203 SoC RTL 仿真中通过 DTCM 预载命令并比较完整响应；它不模拟 UART 引脚的位时序。

本轮当前 RTL 的验证范围和结果见 [E203 逻辑软件验收](../Delivery/E203逻辑软件完整验收.md)。其中 SIMDISPLAY 的 24/24 个逻辑协议用例全部通过：18 个参数/操作组合的有效 KAT，加上 6 个参数各一条篡改密文 Decaps，完整比较 206,082 字节，并检查 117 次 NICE 提交。此前 [1032 条请求的板级串口验收](../evidence/uarthelper_fs_full_20261105_162832/README.md) 发生在本轮 RTL 优化之前，其历史周期和结果不能作为当前 RTL 的重新上板验收。

Scloud 512、ML-KEM 和 ML-DSA 的命令与参考文件用于向量生成及协议匹配设备的验证，不属于当前 HWDISPLAY/SIMDISPLAY 固件支持范围。`PQC-PACE-Frodo` 和 `PQC-PACE-Scloud` 的独立算法测试入口使用 DTCM 二进制输入；手工发送本说明的 ASCII 命令应使用 HWDISPLAY 或 SIMDISPLAY。

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

例如验证 FrodoKEM-SHAKE-640 Encaps 第 2 条：

```sh
sed -n '2p' UARTHELPER/FRODOENCAPS/encaps_commands_640.txt
sed -n '2p' UARTHELPER/FRODOENCAPS/ct_ref_640.txt
sed -n '2p' UARTHELPER/FRODOENCAPS/ss_ref_640.txt
```

加载匹配阶段和参数集的 HWDISPLAY 固件后，以 115200 8N1 发送命令行并补一个换行，等待板端输出 `END`。将 `CT=` 与 `ct_ref`、`SS=` 与 `ss_ref` 逐字节比较。KeyGen 和带 `FAIL_MASK` 的 Decaps 同理；ML-KEM/ML-DSA 需另有匹配固件。长命令及长输出必须关闭串口工具的自动折行/截断；显示折行不能变成实际换行。

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
