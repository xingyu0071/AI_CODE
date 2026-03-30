#!/usr/bin/env python3
"""
文件 SHA256 清单工具（支持递归扫描、任意文件类型，交互式选择）
用法：
    自动检测: python AI_rar_sha256.py [--recursive | --no-recursive] [--extensions .ext1 .ext2 ...]
    生成清单: python AI_rar_sha256.py generate [--recursive | --no-recursive] [--extensions .ext1 .ext2 ...] [--threads N]
    校验清单: python AI_rar_sha256.py verify [--threads N]
"""

import os
import sys
import hashlib
import argparse
import platform
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, List, Union, Set
import colorama

# 默认处理的文件类型（所有文件）
DEFAULT_SUFFIXES = 'all'   # 表示处理所有文件

MANIFEST_NAME = "sha256_manifest.txt"   # 清单文件名
DEFAULT_THREADS = 4                     # 无法获取 CPU 核心数时的默认值
MAX_THREADS_LIMIT = 32                  # 线程数上限
colorama.init()
@dataclass
class VerifyResult:
    """存储单个文件的验证结果"""
    rel_path: str           # 相对路径
    expected_sha: str       # 期望的 SHA256
    actual_sha: Optional[str] = None   # 实际计算的 SHA256，失败时为 None
    error: Optional[str] = None        # 错误信息，无错误则为 None
    match: bool = False     # 是否匹配（仅当成功计算且相等时为 True）

def get_system_info():
    """获取系统硬件信息（CPU 核心数、操作系统等）"""
    cpu_count = os.cpu_count()
    if cpu_count is None:
        cpu_count = DEFAULT_THREADS // 2  # 保守估计
    system = platform.system()
    release = platform.release()
    return cpu_count, system, release

def get_cpu_vendor() -> str:
    """
    检测 CPU 厂商。
    返回 "AMD"、"Intel" 或 "Unknown"。
    """
    try:
        # Windows 平台
        if platform.system() == "Windows":
            # 尝试从环境变量获取
            processor_id = os.environ.get("PROCESSOR_IDENTIFIER", "")
            if "AMD" in processor_id:
                return "AMD"
            elif "Intel" in processor_id:
                return "Intel"
            # 备用：使用 platform.processor()
            proc = platform.processor()
            if "AMD" in proc:
                return "AMD"
            elif "Intel" in proc:
                return "Intel"
        # Linux / Unix 平台
        elif platform.system() == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("vendor_id"):
                        vendor = line.split(":")[1].strip()
                        if vendor in ("AuthenticAMD", "AMD"):
                            return "AMD"
                        elif vendor in ("GenuineIntel", "Intel"):
                            return "Intel"
                        break
        # macOS 平台
        elif platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(["sysctl", "-n", "machdep.cpu.vendor"], capture_output=True, text=True)
            vendor = result.stdout.strip()
            if "AMD" in vendor:
                return "AMD"
            elif "Intel" in vendor:
                return "Intel"
    except Exception:
        pass
    return "Unknown"

def calculate_optimal_threads(cpu_count: int, user_threads: Optional[int] = None, vendor: str = "Unknown") -> int:
    """
    根据 CPU 逻辑核心数、用户指定值和 CPU 厂商计算最佳线程数。
    - 用户指定优先。
    - 若未指定，AMD 使用逻辑核心数 × 2（但不超过上限），非 AMD 使用逻辑核心数（保守策略）。
    """
    if user_threads is not None:
        return max(1, user_threads)  # 用户指定优先

    if vendor == "AMD":
        # AMD 原策略：逻辑核心数 × 2
        threads = max(1, min(cpu_count * 2, MAX_THREADS_LIMIT))
    else:
        # 非 AMD（Intel 等）保守策略：不超过逻辑核心数
        threads = max(1, min(cpu_count, MAX_THREADS_LIMIT))
    return threads

def calculate_sha256(file_path: Path) -> str:
    """计算文件的 SHA256 哈希值，返回十六进制字符串"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        raise RuntimeError(f"读取文件 {file_path} 失败: {e}")

def is_match_suffix(file_path: Path, suffixes: Union[Set[str], str]) -> bool:
    """
    判断文件是否匹配指定的后缀集合。
    如果 suffixes 为 'all'，则匹配所有文件（不过滤）。
    """
    if suffixes == 'all':
        return True
    suffix = file_path.suffix.lower()
    return suffix in suffixes

def generate_manifest(work_dir: Path, extensions: Union[Set[str], str] = 'all', recursive: bool = False):
    """
    扫描当前目录下所有匹配扩展名的文件，生成 SHA256 清单。
    extensions 可以是：
        - 'all'：所有文件（默认）
        - 集合（set）：包含允许的后缀（如 {'.rar', '.txt'}）。
    recursive: 是否递归子目录，默认 False。
    """
    # 确定要使用的后缀集描述
    if extensions == 'all':
        type_desc = "所有文件"
    else:
        type_desc = f"后缀为 {', '.join(sorted(extensions))} 的文件"

    # 获取匹配的文件列表
    files = []
    if recursive:
        # 递归遍历所有子目录
        for entry in work_dir.rglob('*'):
            if entry.is_file() and is_match_suffix(entry, extensions):
                files.append(entry)
    else:
        # 只遍历当前目录
        for entry in work_dir.iterdir():
            if entry.is_file() and is_match_suffix(entry, extensions):
                files.append(entry)

    if not files:
        print(f"未找到任何 {type_desc}。")
        return

    manifest_path = work_dir / MANIFEST_NAME
    print(f"正在生成清单: {manifest_path}")
    print(f"共找到 {len(files)} 个{type_desc}，开始计算哈希值...")

    with open(manifest_path, "w", encoding="utf-8") as mf:
        for idx, file in enumerate(files, 1):
            print(f"  [{idx}/{len(files)}] {file.relative_to(work_dir)}")
            try:
                sha256 = calculate_sha256(file)
                rel_path = file.relative_to(work_dir)
                mf.write(f"{rel_path}\t{sha256}\n")
            except Exception as e:
                print(f"错误: {e}，跳过该文件")
                continue

    print(f"清单已保存至 {manifest_path}")

def process_file(rel_path_str: str, expected_sha: str, work_dir: Path) -> VerifyResult:
    """处理单个文件的验证任务（供线程池调用）"""
    file_path = work_dir / rel_path_str
    if not file_path.exists():
        return VerifyResult(rel_path_str, expected_sha, error="文件不存在")

    try:
        actual_sha = calculate_sha256(file_path)
        match = (actual_sha == expected_sha)
        return VerifyResult(rel_path_str, expected_sha, actual_sha, match=match)
    except Exception as e:
        return VerifyResult(rel_path_str, expected_sha, error=str(e))

def verify_manifest(work_dir: Path, max_workers: int):
    """读取清单，使用多线程验证文件完整性，并打印每个文件的 SHA256"""
    manifest_path = work_dir / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"错误: 清单文件 {manifest_path} 不存在，请先运行生成模式。")
        return

    print(f"正在验证清单: {manifest_path}")
    # 读取所有条目（保持顺序）
    entries = []
    with open(manifest_path, "r", encoding="utf-8") as mf:
        for line_num, line in enumerate(mf, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t', 1)
            if len(parts) != 2:
                print(f"警告: 第 {line_num} 行格式无效，跳过: {line}")
                continue
            entries.append((parts[0], parts[1]))

    if not entries:
        print("清单文件中没有有效的条目。")
        return

    print(f"共读取 {len(entries)} 个条目，使用 {max_workers} 个线程并发验证...")

    # 多线程处理
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_entry = {
            executor.submit(process_file, rel_path, expected_sha, work_dir): (rel_path, expected_sha)
            for rel_path, expected_sha in entries
        }
        for future in as_completed(future_to_entry):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                rel_path, _ = future_to_entry[future]
                results.append(VerifyResult(rel_path, "", error=f"处理时发生意外异常: {e}"))

    # 按原始顺序输出结果
    result_map = {r.rel_path: r for r in results}
    errors = 0
    problem_files = []

    print("\n" + "=" * 60)
    print("详细校验结果:")
    print("=" * 60)

    for rel_path, expected_sha in entries:
        result = result_map.get(rel_path)
        if not result:
            print(f"警告: 未找到 {rel_path} 的结果，跳过")
            continue

        if result.error:
            print(f"错误: {rel_path} - {result.error}")
            errors += 1
            problem_files.append({
                'path': rel_path,
                'status': '错误',
                'detail': result.error
            })
            continue

        if result.match:
            print(f"✓ 通过: {rel_path}")
            print(f"  实际 SHA256: {result.actual_sha}")
            print(f"  期望 SHA256: {result.expected_sha}")
        else:
            print(f"✗ 失败: {rel_path}")
            print(f"  实际 SHA256: {result.actual_sha}")
            print(f"  期望 SHA256: {result.expected_sha}")
            errors += 1
            problem_files.append({
                'path': rel_path,
                'status': '哈希不匹配',
                'detail': f'期望: {result.expected_sha}\n         实际: {result.actual_sha}'
            })

    # 汇总
    print("\n" + "=" * 60)
    print("校验汇总:")
    print("=" * 60)
    if errors == 0:
        print("所有文件均通过校验。")
    else:
        print(f"共发现 {errors} 个问题。")

    # 单独打印问题文件清单
    if problem_files:
        print("\n" + "=" * 60)
        print("问题文件清单:")
        print("=" * 60)
        for idx, problem in enumerate(problem_files, 1):
            print(f"\n{idx}. 文件: {problem['path']}")
            print(f"   状态: {problem['status']}")
            print(f"   详情: {problem['detail']}")
        print("\n" + "=" * 60)

def parse_extensions(ext_list: List[str]) -> Union[Set[str], str]:
    """
    解析用户输入的扩展名列表。
    如果未提供任何扩展名，返回 'all'（表示所有文件）。
    如果列表中包含 'all' 且为唯一的元素，也返回 'all'。
    否则返回规范化的后缀集合（小写，确保以点开头）。
    """
    if not ext_list:
        return 'all'   # 默认处理所有文件

    # 检查是否为 'all'（不区分大小写）
    if len(ext_list) == 1 and ext_list[0].lower() == 'all':
        return 'all'

    suffixes = set()
    for ext in ext_list:
        ext = ext.strip()
        if not ext:
            continue
        # 确保以点开头
        if not ext.startswith('.'):
            ext = '.' + ext
        suffixes.add(ext.lower())
    return suffixes

def has_subdirectories(path: Path) -> bool:
    """检查当前目录下是否存在子文件夹（直接子目录）"""
    try:
        for entry in path.iterdir():
            if entry.is_dir():
                return True
    except PermissionError:
        pass
    return False

def ask_recursive() -> bool:
    """交互式询问用户是否递归扫描子目录"""
    while True:
        answer = input("检测到当前目录下存在子文件夹，是否递归扫描子目录？(y/n): ").strip().lower()
        if answer in ('y', 'yes'):
            return True
        elif answer in ('n', 'no'):
            return False
        else:
            print("请输入 y 或 n。")

def ask_extensions() -> Union[Set[str], str]:
    """交互式询问用户要处理的文件扩展名"""
    print("\n" + "=" * 60)
    print("文件类型选择:")
    print("1. 处理所有文件")
    print("2. 仅处理指定扩展名的文件")
    choice = input("请输入数字 (1/2，默认 1): ").strip()
    if choice == "2":
        ext_input = input("请输入扩展名，多个用空格分隔（例如 .rar .zip .txt）: ").strip()
        if ext_input:
            return parse_extensions(ext_input.split())
        else:
            print("未输入扩展名，将处理所有文件。")
            return 'all'
    else:
        return 'all'

def run_operation(mode, work_dir, extensions, recursive, optimal_threads):
    """执行生成或验证操作"""
    if mode is None:
        # 自动模式
        manifest_path = work_dir / MANIFEST_NAME
        if manifest_path.exists():
            verify_manifest(work_dir, optimal_threads)
        else:
            generate_manifest(work_dir, extensions, recursive)
    elif mode == "generate":
        generate_manifest(work_dir, extensions, recursive)
    else:  # verify
        verify_manifest(work_dir, optimal_threads)

def main():
    parser = argparse.ArgumentParser(
        description="文件 SHA256 清单工具（支持递归扫描、任意文件类型，交互式选择）",
        epilog="默认处理当前目录下所有文件（非递归），可通过 --extensions 过滤类型。若未指定递归参数且存在子目录，将交互询问。"
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["generate", "verify"],
        help="操作模式: generate 生成清单, verify 校验清单（不指定则自动检测）"
    )
    parser.add_argument(
        "--extensions", "-e",
        nargs="+",
        help="要处理的文件扩展名（例如 .rar .txt .pdf），多个用空格分隔；默认处理所有文件。"
    )
    # 递归参数组：--recursive 和 --no-recursive 互斥
    rec_group = parser.add_mutually_exclusive_group()
    rec_group.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="强制递归扫描子目录（优先级高于交互询问）"
    )
    rec_group.add_argument(
        "--no-recursive", "-nr",
        action="store_true",
        help="强制不递归扫描子目录（优先级高于交互询问）"
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        help="校验时使用的线程数（默认根据 CPU 核心数自动计算）"
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="禁用操作结束后的交互提示（用于自动化脚本）"
    )
    args = parser.parse_args()

    # 获取工作目录
    work_dir = Path.cwd()
    print(f"工作目录: {work_dir}")

    # 获取系统信息
    cpu_count, os_name, os_version = get_system_info()
    print(f"系统信息: {os_name} {os_version} | CPU 逻辑核心数: {cpu_count}")

    # 获取 CPU 厂商
    cpu_vendor = get_cpu_vendor()
    print(f"CPU 厂商: {cpu_vendor}")

    # 确定线程数（优先命令行参数，其次环境变量，最后自动计算）
    user_threads = args.threads
    if user_threads is None:
        env_threads = os.environ.get("RAR_SHA256_THREADS")
        if env_threads is not None:
            try:
                user_threads = int(env_threads)
            except ValueError:
                print(f"警告: 环境变量 RAR_SHA256_THREADS 值无效，将使用自动计算。")
    optimal_threads = calculate_optimal_threads(cpu_count, user_threads, cpu_vendor)
    if user_threads is not None:
        print(f"线程数: 用户指定 {optimal_threads}")
    else:
        if cpu_vendor == "AMD":
            print(f"线程数: AMD 优化策略 {optimal_threads} (逻辑核心数 × 2，上限 {MAX_THREADS_LIMIT})")
            print(colorama.Fore.RED + '本工具 由 AI（*）生成，仅供 学习交流使用。请自行承担使用风险，作者不对任何损失负责。' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + 'This tool is generated by AI (*) and is intended for learning purposes only. Use it at your own risk. The author assumes no responsibility for any damage or data loss.' + colorama.Style.RESET_ALL)
        else:
            print(f"线程数: 保守策略 {optimal_threads} (逻辑核心数，上限 {MAX_THREADS_LIMIT})")
            print(colorama.Fore.RED + '本工具 由 AI（*）生成，仅供 学习交流使用。请自行承担使用风险，作者不对任何损失负责。' + colorama.Style.RESET_ALL)
            print(colorama.Fore.RED + 'This tool is generated by AI (*) and is intended for learning purposes only. Use it at your own risk. The author assumes no responsibility for any damage or data loss.' + colorama.Style.RESET_ALL)

    # 解析扩展名（优先命令行，否则交互询问）
    if args.extensions is not None:
        extensions = parse_extensions(args.extensions)
    else:
        # 未通过命令行指定扩展名，则判断是否自动模式（无交互）或交互询问
        if args.no_prompt or os.environ.get("DISABLE_PROMPT") == "1":
            extensions = 'all'
        else:
            extensions = ask_extensions()

    if extensions == 'all':
        print("文件类型: 所有文件")
    else:
        print(f"文件类型: 后缀为 {', '.join(sorted(extensions))} 的文件")

    # 确定递归标志
    recursive = False
    if args.recursive:
        recursive = True
        print("扫描模式: 递归扫描子目录（强制）")
    elif args.no_recursive:
        recursive = False
        print("扫描模式: 仅当前目录（强制）")
    else:
        # 未指定任何递归参数，则检测是否存在子文件夹并询问用户
        if has_subdirectories(work_dir):
            print("检测到当前目录下存在子文件夹。")
            recursive = ask_recursive()
            print(f"扫描模式: {'递归扫描子目录' if recursive else '仅当前目录'}")
        else:
            recursive = False
            print("扫描模式: 仅当前目录（当前目录下无子文件夹）")

    # 执行一次操作
    run_operation(args.mode, work_dir, extensions, recursive, optimal_threads)

    # 如果启用了 --no-prompt 或环境变量 DISABLE_PROMPT=1，则直接退出，不显示交互菜单
    disable_prompt = args.no_prompt or os.environ.get("DISABLE_PROMPT") == "1"
    if disable_prompt:
        return

    # 交互式循环：让用户选择重新运行或退出
    while True:
        print("\n" + "=" * 60)
        choice = input("操作完成。按 'r' 重新运行 (相同设置)，按 'q' 退出: ").strip().lower()
        if choice == 'r':
            print("\n" + "=" * 60)
            print("重新运行...")
            run_operation(args.mode, work_dir, extensions, recursive, optimal_threads)
        elif choice == 'q':
            print("退出程序。")
            break
        else:
            print("无效输入，请输入 'r' 或 'q'。")

if __name__ == "__main__":
    main()
