#!/usr/bin/env python3
import psutil
import time
import logging
import os
import signal
from collections import defaultdict
from datetime import datetime

# 配置日志
logging.basicConfig(
    filename='process_monitor.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 配置参数
CPU_THRESHOLD = 95  # CPU使用率阈值（百分比）
MONITOR_INTERVAL = 1  # 检查间隔（秒）
DURATION_THRESHOLD = 40  # 持续时间阈值（秒）

# 存储进程的CPU使用记录
process_history = defaultdict(list)

def get_process_info():
    """获取所有进程的信息"""
    processes = {}
    
    try:
        # 获取系统总CPU时间作为基准
        total_cpu_percent = psutil.cpu_percent(interval=1)
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # 获取进程详细信息
                pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                pid = pinfo['pid']
                
                # 获取进程CPU使用率
                proc_cpu_percent = proc.cpu_percent(interval=None)
                
                # 如果CPU使用率大于阈值，再次确认
                if proc_cpu_percent > CPU_THRESHOLD:
                    # 等待短暂时间后再次测量
                    time.sleep(0.1)
                    proc_cpu_percent = proc.cpu_percent(interval=0.1)
                
                processes[pid] = {
                    'name': pinfo['name'],
                    'cpu_percent': proc_cpu_percent,
                    'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else pinfo['name']
                }
                
                # 记录检测到的高CPU使用率进程
                if proc_cpu_percent > CPU_THRESHOLD:
                    logging.info(
                        f"检测到高CPU进程 - PID: {pid}, "
                        f"名称: {pinfo['name']}, "
                        f"CPU: {proc_cpu_percent:.1f}%"
                    )
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.debug(f"获取进程信息失败: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"获取进程信息时发生错误: {str(e)}")
        return {}
        
    return processes

def kill_process(pid, name, cpu_percent):
    """强制终止进程"""
    try:
        # 首先尝试使用SIGTERM温和地终止进程
        os.kill(pid, signal.SIGTERM)
        
        # 等待进程结束
        for _ in range(30):  # 最多等待3秒
            try:
                # 如果进程不存在了，os.kill会抛出异常
                os.kill(pid, 0)
                time.sleep(0.1)
            except OSError:
                logging.info(f"进程已成功终止 - PID: {pid}")
                return True
        
        # 如果进程仍然存在，使用SIGKILL强制终止
        os.kill(pid, signal.SIGKILL)
        logging.warning(f"使用SIGKILL强制终止进程 - PID: {pid}")
        return True
        
    except ProcessLookupError:
        logging.info(f"进程已不存在 - PID: {pid}")
        return True
    except PermissionError:
        logging.error(f"没有权限终止进程 - PID: {pid}")
        return False
    except Exception as e:
        logging.error(f"终止进程时发生错误 - PID: {pid}, 错误: {str(e)}")
        return False

def check_and_kill_processes():
    """检查并终止高资源使用率的进程"""
    current_time = time.time()
    processes = get_process_info()

    for pid, info in processes.items():
        cpu_percent = info['cpu_percent']
        
        # 跳过系统关键进程
        if info['name'].lower() in ['systemd', 'init', 'kernel', 'kthreadd', 'watchdog']:
            continue
            
        if cpu_percent > CPU_THRESHOLD:
            process_history[pid].append((current_time, cpu_percent))
            
            # 清理超过监控时间窗口的历史记录
            process_history[pid] = [
                x for x in process_history[pid] 
                if current_time - x[0] <= DURATION_THRESHOLD
            ]
            
            # 记录进程历史信息
            logging.debug(
                f"进程历史记录 - PID: {pid}, "
                f"记录数: {len(process_history[pid])}, "
                f"持续时间: {len(process_history[pid]) * MONITOR_INTERVAL}秒"
            )
            
            # 检查是否持续高CPU使用
            if len(process_history[pid]) * MONITOR_INTERVAL >= DURATION_THRESHOLD:
                if kill_process(pid, info['name'], cpu_percent):
                    print(f"已终止进程 PID: {pid}, 名称: {info['name']}, "
                          f"CPU: {cpu_percent:.1f}%, 持续时间: {len(process_history[pid]) * MONITOR_INTERVAL}秒")
                    del process_history[pid]
        else:
            # 如果CPU使用率降低，清除历史记录
            if pid in process_history:
                del process_history[pid]

def main():
    if os.geteuid() != 0:
        print("错误：此脚本需要root权限运行！")
        print("请使用 'sudo python3 process_monitor.py' 运行")
        return

    logging.info(
        f"进程监控工具已启动\n"
        f"CPU阈值: {CPU_THRESHOLD}%\n"
        f"监控间隔: {MONITOR_INTERVAL}秒\n"
        f"持续时间阈值: {DURATION_THRESHOLD}秒"
    )
    print(f"进程监控工具已启动\n"
          f"CPU阈值: {CPU_THRESHOLD}%\n"
          f"监控间隔: {MONITOR_INTERVAL}秒\n"
          f"持续时间阈值: {DURATION_THRESHOLD}秒\n"
          f"日志记录在: process_monitor.log")
    
    try:
        while True:
            check_and_kill_processes()
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        logging.info("进程监控工具已停止")
        print("\n进程监控工具已停止")

def monitor_process(process_name):
    start_time = time.time()
    while True:
        try:
            # 获取进程
            process = psutil.Process(get_pid_by_name(process_name))
            
            # 计算运行时间（修复计时更新）
            current_time = time.time()
            elapsed_time = int(current_time - start_time)
            
            # 获取CPU和内存使用情况
            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            
            # 记录信息
            log_message = f"运行时间: {elapsed_time}秒, CPU使用率: {cpu_percent}%, 内存使用: {memory_info.rss / 1024 / 1024:.2f}MB"
            logging.info(log_message)
            print(log_message)
            
            time.sleep(1)  # 每秒更新一次
            
        except Exception as e:
            logging.error(f"监控出错: {str(e)}")
            print(f"监控出错: {str(e)}")
            break

if __name__ == "__main__":
    main() 