"""
凭证管理器 - 完全基于统一存储中间层
"""
import asyncio
import time
import random
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from contextlib import asynccontextmanager

from config import get_calls_per_rotation, is_mongodb_mode
from log import log
from .storage_adapter import get_storage_adapter
from .google_oauth_api import fetch_user_email_from_file, Credentials
from .task_manager import task_manager


class CredentialManager:
    """
    统一凭证管理器
    所有存储操作通过storage_adapter进行
    """
    
    def __init__(self):
        # 核心状态
        self._initialized = False
        self._storage_adapter = None
        
        # 凭证轮换相关
        self._credential_files: List[str] = []  # 存储凭证文件名列表
        self._last_scan_time = 0
        
        # 回退模式相关
        self._fallback_mode = False  # 是否处于回退模式（顺序调用）
        self._fallback_index = 0  # 回退模式下的当前索引
        self._random_failure_count = 0  # 随机模式连续失败次数
        self._fallback_threshold = 3  # 连续失败多少次后回退到顺序模式
        self._recovery_attempt_count = 0  # 恢复尝试次数
        self._recovery_threshold = 10  # 每尝试多少次检查一次是否可以恢复随机模式
        
        # 当前使用的凭证信息
        self._current_credential_file: Optional[str] = None
        self._current_credential_data: Optional[Dict[str, Any]] = None
        self._current_credential_state: Dict[str, Any] = {}
        
        # 并发控制
        self._state_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        
        # 工作线程控制
        self._shutdown_event = asyncio.Event()
        self._write_worker_running = False
        self._write_worker_task = None
        
        # 原子操作计数器
        self._atomic_counter = 0
        self._atomic_lock = asyncio.Lock()
        
        # Onboarding state
        self._onboarding_complete = False
        self._onboarding_checked = False
    
    async def initialize(self):
        """初始化凭证管理器"""
        async with self._state_lock:
            if self._initialized:
                return
            
            # 初始化统一存储适配器
            self._storage_adapter = await get_storage_adapter()
            
            # 启动后台工作线程
            await self._start_background_workers()
            
            # 发现并加载凭证
            await self._discover_credentials()
            
            self._initialized = True
            storage_type = "MongoDB" if await is_mongodb_mode() else "File"
            log.debug(f"Credential manager initialized with {storage_type} storage backend")
    
    async def close(self):
        """清理资源"""
        log.debug("Closing credential manager...")
        
        # 设置关闭标志
        self._shutdown_event.set()
        
        # 等待后台任务结束
        if self._write_worker_task:
            try:
                await asyncio.wait_for(self._write_worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("Write worker task did not finish within timeout")
                if not self._write_worker_task.done():
                    self._write_worker_task.cancel()
        
        self._initialized = False
        log.debug("Credential manager closed")
    
    async def _start_background_workers(self):
        """启动后台工作线程"""
        if not self._write_worker_running:
            self._write_worker_running = True
            self._write_worker_task = task_manager.create_task(
                self._background_worker(), 
                name="credential_background_worker"
            )
    
    async def _background_worker(self):
        """后台工作线程，处理定期任务"""
        while not self._shutdown_event.is_set():
            try:
                # 每60秒检查一次凭证更新
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=60.0)
                if self._shutdown_event.is_set():
                    break
                
                # 重新发现凭证（热更新）
                await self._discover_credentials()
                
            except asyncio.TimeoutError:
                # 超时是正常的，继续下一轮
                continue
            except Exception as e:
                log.error(f"Background worker error: {e}")
                await asyncio.sleep(5)  # 错误后等待5秒再继续
    
    async def _discover_credentials(self):
        """发现和加载所有可用凭证"""
        try:
            # 从存储适配器获取所有凭证
            all_credentials = await self._storage_adapter.list_credentials()
            
            # 过滤出可用的凭证（排除被禁用的）- 批量读取状态以提升性能
            available_credentials = []
            
            # 批量获取所有凭证状态，避免多次读取状态文件
            if all_credentials:
                try:
                    all_states = await self._storage_adapter.get_all_credential_states()
                    
                    for credential_name in all_credentials:
                        normalized_name = credential_name
                        # 标准化文件名以匹配状态数据中的键
                        if hasattr(self._storage_adapter._backend, '_normalize_filename'):
                            normalized_name = self._storage_adapter._backend._normalize_filename(credential_name)
                        
                        state = all_states.get(normalized_name, {})
                        if not state.get("disabled", False):
                            available_credentials.append(credential_name)
                except Exception as e:
                    log.warning(f"Failed to batch load credential states, falling back to individual checks: {e}")
                    # 如果批量读取失败，回退到逐个检查
                    for credential_name in all_credentials:
                        try:
                            state = await self._storage_adapter.get_credential_state(credential_name)
                            if not state.get("disabled", False):
                                available_credentials.append(credential_name)
                        except Exception as e2:
                            log.warning(f"Failed to check state for credential {credential_name}: {e2}")
            
            # 更新凭证列表
            old_credentials = set(self._credential_files)
            new_credentials = set(available_credentials)
            
            if old_credentials != new_credentials:
                # 记录变化（只在非初始状态时记录）
                is_initial_load = len(old_credentials) == 0
                added = new_credentials - old_credentials
                removed = old_credentials - new_credentials
                
                self._credential_files = available_credentials
                
                # 初始加载时只记录调试信息，运行时变化才记录INFO
                if not is_initial_load:
                    if added:
                        log.info(f"发现新的可用凭证: {list(added)}")
                    if removed:
                        log.info(f"移除不可用凭证: {list(removed)}")
                else:
                    # 初始加载时只记录调试信息
                    if available_credentials:
                        log.debug(f"初始加载发现 {len(available_credentials)} 个可用凭证")
            
            if not self._credential_files:
                log.warning("No available credential files found")
            else:
                log.debug(f"Available credentials: {len(self._credential_files)} files")
                
        except Exception as e:
            log.error(f"Failed to discover credentials: {e}")
    
    async def _load_current_credential(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        """加载当前选中的凭证数据，包含token过期检测和自动刷新"""
        if not self._credential_files or not self._current_credential_file:
            return None
        
        try:
            current_file = self._current_credential_file
            
            # 从存储适配器加载凭证数据
            credential_data = await self._storage_adapter.get_credential(current_file)
            if not credential_data:
                log.error(f"Failed to load credential data for: {current_file}")
                return None
            
            # 检查refresh_token
            if "refresh_token" not in credential_data or not credential_data["refresh_token"]:
                log.warning(f"No refresh token in {current_file}")
                return None
                
            # Auto-add 'type' field if missing but has required OAuth fields
            if 'type' not in credential_data and all(key in credential_data for key in ['client_id', 'refresh_token']):
                credential_data['type'] = 'authorized_user'
                log.debug(f"Auto-added 'type' field to credential from file {current_file}")
            
            # 兼容不同的token字段格式
            if "access_token" in credential_data and "token" not in credential_data:
                credential_data["token"] = credential_data["access_token"]
            if "scope" in credential_data and "scopes" not in credential_data:
                credential_data["scopes"] = credential_data["scope"].split()
            
            # token过期检测和刷新
            should_refresh = await self._should_refresh_token(credential_data)
            
            if should_refresh:
                log.debug(f"Token需要刷新 - 文件: {current_file}")
                refreshed_data = await self._refresh_token(credential_data, current_file)
                if refreshed_data:
                    credential_data = refreshed_data
                    log.debug(f"Token刷新成功: {current_file}")
                else:
                    log.error(f"Token刷新失败: {current_file}")
                    return None
            
            # 加载状态信息
            state_data = await self._storage_adapter.get_credential_state(current_file)
            
            # 缓存当前凭证信息
            self._current_credential_file = current_file
            self._current_credential_data = credential_data
            self._current_credential_state = state_data
            
            return current_file, credential_data
            
        except Exception as e:
            log.error(f"Error loading current credential: {e}")
            return None
    
    async def get_valid_credential(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        """获取有效的凭证，支持随机选择和顺序回退机制"""
        async with self._operation_lock:
            if not self._credential_files:
                await self._discover_credentials()
                if not self._credential_files:
                    return None
            
            # 尝试恢复随机模式（如果处于回退模式）
            await self._try_recover_from_fallback()
            
            # 根据当前模式选择凭证
            selected_credential = None
            selection_error = None
            
            try:
                if self._fallback_mode:
                    # 回退模式：使用顺序选择
                    selected_credential = self._select_credential_by_sequential()
                    log.debug(f"回退模式选择凭证: {selected_credential}")
                else:
                    # 正常模式：使用随机选择
                    selected_credential = await self._select_credential_by_weighted_random()
                    log.debug(f"随机模式选择凭证: {selected_credential}")
                    
            except Exception as e:
                selection_error = e
                log.error(f"凭证选择失败: {e}")
                self._random_failure_count += 1
                
                # 如果随机选择失败次数超过阈值，进入回退模式
                if self._random_failure_count >= self._fallback_threshold:
                    self._enter_fallback_mode()
                    
                    # 使用顺序选择作为回退
                    try:
                        selected_credential = self._select_credential_by_sequential()
                        log.info(f"使用回退模式选择凭证: {selected_credential}")
                    except Exception as fallback_error:
                        log.error(f"回退模式选择也失败: {fallback_error}")
                        return None
            
            if not selected_credential:
                log.error("无法选择凭证")
                return None
            
            # 尝试加载选中的凭证，如果失败则尝试其他凭证
            max_attempts = len(self._credential_files)
            attempted_credentials = set()
            
            for attempt in range(max_attempts):
                try:
                    # 如果当前选择的凭证已经尝试过，重新选择
                    if selected_credential in attempted_credentials:
                        remaining_credentials = [c for c in self._credential_files if c not in attempted_credentials]
                        if not remaining_credentials:
                            break
                        
                        # 根据当前模式重新选择
                        if self._fallback_mode:
                            # 在回退模式下，直接从剩余凭证中按顺序选择
                            selected_credential = remaining_credentials[0]
                        else:
                            # 在随机模式下，从剩余凭证中随机选择
                            selected_credential = random.choice(remaining_credentials)
                    
                    attempted_credentials.add(selected_credential)
                    
                    # 设置当前凭证并尝试加载
                    self._current_credential_file = selected_credential
                    result = await self._load_current_credential()
                    
                    if result:
                        # 成功加载，重置失败计数
                        if not self._fallback_mode:
                            self._random_failure_count = 0
                        log.debug(f"成功选择并加载凭证: {selected_credential}")
                        return result
                    
                    # 当前凭证加载失败，标记为失效
                    log.warning(f"凭证失效，自动禁用: {selected_credential}")
                    await self.set_cred_disabled(selected_credential, True)
                    
                    # 重新发现可用凭证（排除刚禁用的）
                    await self._discover_credentials()
                    if not self._credential_files:
                        log.error("没有可用的凭证")
                        return None
                    
                    # 如果没有剩余未尝试的凭证，退出
                    remaining_credentials = [c for c in self._credential_files if c not in attempted_credentials]
                    if not remaining_credentials:
                        log.error("所有可用凭证都已尝试失败")
                        break
                        
                    # 根据当前模式重新选择下一个凭证
                    try:
                        if self._fallback_mode:
                            selected_credential = self._select_credential_by_sequential()
                        else:
                            selected_credential = await self._select_credential_by_weighted_random()
                    except Exception as selection_retry_error:
                        log.error(f"重新选择凭证失败: {selection_retry_error}")
                        # 如果随机选择再次失败，强制进入回退模式
                        if not self._fallback_mode:
                            self._random_failure_count += 1
                            if self._random_failure_count >= self._fallback_threshold:
                                self._enter_fallback_mode()
                                selected_credential = self._select_credential_by_sequential()
                        
                    if not selected_credential:
                        break
                        
                except Exception as e:
                    log.error(f"加载凭证时发生异常 {selected_credential} (尝试 {attempt + 1}/{max_attempts}): {e}")
                    continue
            
            log.error(f"所有 {max_attempts} 个凭证都尝试失败")
            return None
    
    async def _should_rotate(self) -> bool:
        """检查是否需要轮换凭证"""
        if not self._credential_files or len(self._credential_files) <= 1:
            return False
        
        # 注意：现在使用随机选择，不再需要基于调用次数的轮换检查
        # 这个方法保留是为了兼容性，但总是返回False
        return False
    
    async def force_rotate_credential(self):
        """强制选择新凭证（用于429错误处理）"""
        async with self._operation_lock:
            if len(self._credential_files) <= 1:
                log.warning("Only one credential available, cannot rotate")
                return
            
            # 简单地重新选择一个凭证（随机）
            log.info("Forced credential rotation due to rate limit")
    
    async def _get_credential_usage_stats(self) -> Dict[str, int]:
        """获取所有凭证的使用次数统计"""
        usage_stats = {}
        try:
            # 获取所有凭证状态
            all_states = await self._storage_adapter.get_all_credential_states()
            
            for credential_name in self._credential_files:
                # 标准化文件名
                normalized_name = credential_name
                try:
                    if (hasattr(self._storage_adapter, '_backend') and 
                        hasattr(self._storage_adapter._backend, '_normalize_filename')):
                        normalized_name = self._storage_adapter._backend._normalize_filename(credential_name)
                except Exception:
                    # 如果标准化失败，使用原文件名
                    pass
                
                state = all_states.get(normalized_name, {})
                usage_stats[credential_name] = state.get("usage_count", 0)
                
        except Exception as e:
            log.warning(f"Failed to get usage stats, defaulting to 0: {e}")
            # 如果获取失败，所有凭证使用次数都设为0
            for credential_name in self._credential_files:
                usage_stats[credential_name] = 0
                
        return usage_stats
    
    async def _select_credential_by_weighted_random(self) -> Optional[str]:
        """基于使用次数的加权随机选择凭证，使用次数少的概率更高"""
        if not self._credential_files:
            return None
            
        if len(self._credential_files) == 1:
            return self._credential_files[0]
        
        try:
            # 获取使用统计
            usage_stats = await self._get_credential_usage_stats()
            
            # 计算反向权重（使用次数少的权重高）
            weights = []
            max_usage = max(usage_stats.values()) if usage_stats.values() else 0
            
            for credential_name in self._credential_files:
                usage_count = usage_stats.get(credential_name, 0)
                # 反向权重：最大使用次数 - 当前使用次数 + 1
                # 这样使用次数少的权重更高
                weight = max_usage - usage_count + 1
                weights.append(weight)
            
            # 确保权重有效
            if not weights or all(w <= 0 for w in weights):
                # 如果权重无效，给所有凭证相等权重
                weights = [1] * len(self._credential_files)
            
            # 加权随机选择
            selected_credential = random.choices(self._credential_files, weights=weights, k=1)[0]
            
            log.debug(f"加权随机选择凭证: {selected_credential}, 权重分布: {dict(zip(self._credential_files, weights))}")
            return selected_credential
            
        except Exception as e:
            log.error(f"加权随机选择失败，使用普通随机选择: {e}")
            # 如果加权选择失败，回退到简单随机选择
            return random.choice(self._credential_files)
    
    def _select_credential_by_sequential(self) -> Optional[str]:
        """顺序选择凭证（回退模式）"""
        if not self._credential_files:
            return None
            
        if len(self._credential_files) == 1:
            return self._credential_files[0]
        
        # 使用回退索引进行顺序选择
        selected_credential = self._credential_files[self._fallback_index]
        
        # 更新索引，循环到下一个
        self._fallback_index = (self._fallback_index + 1) % len(self._credential_files)
        
        log.debug(f"顺序选择凭证: {selected_credential} (索引: {self._fallback_index - 1})")
        return selected_credential
    
    async def _try_recover_from_fallback(self) -> bool:
        """尝试从回退模式恢复到随机模式"""
        if not self._fallback_mode:
            return True
            
        self._recovery_attempt_count += 1
        
        # 每达到恢复阈值次数，尝试一次随机选择
        if self._recovery_attempt_count >= self._recovery_threshold:
            self._recovery_attempt_count = 0
            
            try:
                # 尝试一次随机选择
                test_credential = await self._select_credential_by_weighted_random()
                if test_credential:
                    # 成功了，重置计数器并退出回退模式
                    self._random_failure_count = 0
                    self._fallback_mode = False
                    log.info("成功从回退模式恢复到随机选择模式")
                    return True
            except Exception as e:
                log.debug(f"恢复随机模式尝试失败: {e}")
                
        return False
    
    def _enter_fallback_mode(self):
        """进入回退模式"""
        if not self._fallback_mode:
            self._fallback_mode = True
            self._fallback_index = 0
            self._recovery_attempt_count = 0
            log.warning(f"随机选择连续失败 {self._random_failure_count} 次，进入顺序调用回退模式")
    
    async def increment_credential_usage(self, credential_name: str):
        """增加指定凭证的使用计数"""
        try:
            current_state = await self._storage_adapter.get_credential_state(credential_name)
            current_usage = current_state.get("usage_count", 0)
            
            await self.update_credential_state(credential_name, {
                "usage_count": current_usage + 1,
                "last_used": datetime.now(timezone.utc).isoformat()
            })
            
            log.debug(f"凭证 {credential_name} 使用次数增加到: {current_usage + 1}")
            
        except Exception as e:
            log.error(f"更新凭证使用次数失败 {credential_name}: {e}")
    
    def increment_call_count(self):
        """增加调用计数 - 此方法现在仅用于兼容性，实际计数在increment_credential_usage中"""
        log.debug(f"API调用完成")  # 仅记录调用，不再维护全局计数
    
    async def check_and_rotate_if_needed(self):
        """检查并在需要时进行轮换（现在改为更新使用计数）"""
        # 现在不再进行基于次数的轮换，而是更新当前凭证的使用计数
        if self._current_credential_file:
            await self.increment_credential_usage(self._current_credential_file)
        return False
    
    def get_fallback_status(self) -> Dict[str, Any]:
        """获取回退模式状态信息"""
        return {
            "is_fallback_mode": self._fallback_mode,
            "fallback_index": self._fallback_index,
            "random_failure_count": self._random_failure_count,
            "fallback_threshold": self._fallback_threshold,
            "recovery_attempt_count": self._recovery_attempt_count,
            "recovery_threshold": self._recovery_threshold,
            "total_credentials": len(self._credential_files),
            "current_credential": self._current_credential_file
        }
    
    def force_exit_fallback_mode(self):
        """强制退出回退模式"""
        if self._fallback_mode:
            self._fallback_mode = False
            self._random_failure_count = 0
            self._recovery_attempt_count = 0
            log.info("强制退出回退模式，恢复到随机选择模式")
            return True
        return False
    
    def force_enter_fallback_mode(self):
        """强制进入回退模式"""
        if not self._fallback_mode:
            self._enter_fallback_mode()
            return True
        return False
    
    def configure_fallback_settings(self, fallback_threshold: int = None, recovery_threshold: int = None):
        """配置回退模式参数"""
        if fallback_threshold is not None:
            self._fallback_threshold = max(1, fallback_threshold)
            log.info(f"回退阈值设置为: {self._fallback_threshold}")
        
        if recovery_threshold is not None:
            self._recovery_threshold = max(1, recovery_threshold)
            log.info(f"恢复检查阈值设置为: {self._recovery_threshold}")
        
        return {
            "fallback_threshold": self._fallback_threshold,
            "recovery_threshold": self._recovery_threshold
        }
    
    async def update_credential_state(self, credential_name: str, state_updates: Dict[str, Any]):
        """更新凭证状态"""
        try:
            # 直接通过存储适配器更新状态
            success = await self._storage_adapter.update_credential_state(credential_name, state_updates)
            
            # 如果是当前使用的凭证，更新缓存
            if credential_name == self._current_credential_file:
                self._current_credential_state.update(state_updates)
            
            if success:
                log.debug(f"Updated credential state: {credential_name}")
            else:
                log.warning(f"Failed to update credential state: {credential_name}")
                
            return success
            
        except Exception as e:
            log.error(f"Error updating credential state {credential_name}: {e}")
            return False
    
    async def set_cred_disabled(self, credential_name: str, disabled: bool):
        """设置凭证的启用/禁用状态"""
        try:
            state_updates = {"disabled": disabled}
            success = await self.update_credential_state(credential_name, state_updates)
            
            if success:
                # 如果禁用了当前正在使用的凭证，清除当前凭证
                if disabled and credential_name == self._current_credential_file:
                    self._current_credential_file = None
                    await self._discover_credentials()
                
                action = "disabled" if disabled else "enabled"
                log.info(f"Credential {action}: {credential_name}")
            
            return success
            
        except Exception as e:
            log.error(f"Error setting credential disabled state {credential_name}: {e}")
            return False
    
    async def get_creds_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有凭证的状态"""
        try:
            # 从存储适配器获取所有状态
            all_states = await self._storage_adapter.get_all_credential_states()
            return all_states
            
        except Exception as e:
            log.error(f"Error getting credential statuses: {e}")
            return {}
    
    async def get_or_fetch_user_email(self, credential_name: str) -> Optional[str]:
        """获取或获取用户邮箱地址"""
        try:
            # 首先检查缓存的状态
            state = await self._storage_adapter.get_credential_state(credential_name)
            cached_email = state.get("user_email")
            
            if cached_email:
                return cached_email
            
            # 如果没有缓存，从凭证数据获取
            credential_data = await self._storage_adapter.get_credential(credential_name)
            if not credential_data:
                return None
            
            # 尝试获取邮箱
            email = await fetch_user_email_from_file(credential_data)
            
            if email:
                # 缓存邮箱地址
                await self.update_credential_state(credential_name, {"user_email": email})
                return email
            
            return None
            
        except Exception as e:
            log.error(f"Error fetching user email for {credential_name}: {e}")
            return None
    
    async def record_api_call_result(self, credential_name: str, success: bool, error_code: Optional[int] = None):
        """记录API调用结果"""
        try:
            state_updates = {}
            
            if success:
                state_updates["last_success"] = time.time()
                # 清除错误码（如果之前有的话）
                state_updates["error_codes"] = []
            elif error_code:
                # 记录错误码
                current_state = await self._storage_adapter.get_credential_state(credential_name)
                error_codes = current_state.get("error_codes", [])
                
                if error_code not in error_codes:
                    error_codes.append(error_code)
                    # 限制错误码列表长度
                    if len(error_codes) > 10:
                        error_codes = error_codes[-10:]
                    
                state_updates["error_codes"] = error_codes
            
            if state_updates:
                await self.update_credential_state(credential_name, state_updates)
                
        except Exception as e:
            log.error(f"Error recording API call result for {credential_name}: {e}")
    
    # 原子操作支持
    @asynccontextmanager
    async def _atomic_operation(self, operation_name: str):
        """原子操作上下文管理器"""
        async with self._atomic_lock:
            self._atomic_counter += 1
            operation_id = self._atomic_counter
            log.debug(f"开始原子操作[{operation_id}]: {operation_name}")
            
            try:
                yield operation_id
                log.debug(f"完成原子操作[{operation_id}]: {operation_name}")
            except Exception as e:
                log.error(f"原子操作[{operation_id}]失败: {operation_name} - {e}")
                raise
    
    async def _should_refresh_token(self, credential_data: Dict[str, Any]) -> bool:
        """检查token是否需要刷新"""
        try:
            # 如果没有access_token或过期时间，需要刷新
            if not credential_data.get("access_token") and not credential_data.get("token"):
                log.debug("没有access_token，需要刷新")
                return True
                
            expiry_str = credential_data.get("expiry")
            if not expiry_str:
                log.debug("没有过期时间，需要刷新")
                return True
                
            # 解析过期时间
            try:
                if isinstance(expiry_str, str):
                    if "+" in expiry_str:
                        file_expiry = datetime.fromisoformat(expiry_str)
                    elif expiry_str.endswith("Z"):
                        file_expiry = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                    else:
                        file_expiry = datetime.fromisoformat(expiry_str)
                else:
                    log.debug("过期时间格式无效，需要刷新")
                    return True
                    
                # 确保时区信息
                if file_expiry.tzinfo is None:
                    file_expiry = file_expiry.replace(tzinfo=timezone.utc)
                    
                # 检查是否还有至少5分钟有效期
                now = datetime.now(timezone.utc)
                time_left = (file_expiry - now).total_seconds()
                
                log.debug(f"Token剩余时间: {int(time_left/60)}分钟")
                
                if time_left > 300:  # 5分钟缓冲
                    return False
                else:
                    log.debug(f"Token即将过期（剩余{int(time_left/60)}分钟），需要刷新")
                    return True
                    
            except Exception as e:
                log.warning(f"解析过期时间失败: {e}，需要刷新")
                return True
                
        except Exception as e:
            log.error(f"检查token过期时出错: {e}")
            return True
    
    async def _refresh_token(self, credential_data: Dict[str, Any], filename: str) -> Optional[Dict[str, Any]]:
        """刷新token并更新存储"""
        try:
            # 创建Credentials对象
            creds = Credentials.from_dict(credential_data)
            
            # 检查是否可以刷新
            if not creds.refresh_token:
                log.error(f"没有refresh_token，无法刷新: {filename}")
                return None
                
            # 刷新token
            log.debug(f"正在刷新token: {filename}")
            await creds.refresh()
            
            # 更新凭证数据
            if creds.access_token:
                credential_data["access_token"] = creds.access_token
                # 保持兼容性
                credential_data["token"] = creds.access_token
                
            if creds.expires_at:
                credential_data["expiry"] = creds.expires_at.isoformat()
                
            # 保存到存储
            await self._storage_adapter.store_credential(filename, credential_data)
            log.info(f"Token刷新成功并已保存: {filename}")
            
            return credential_data
            
        except Exception as e:
            error_msg = str(e)
            log.error(f"Token刷新失败 {filename}: {error_msg}")
            
            # 检查是否是凭证永久失效的错误
            is_permanent_failure = self._is_permanent_refresh_failure(error_msg)
            
            if is_permanent_failure:
                log.warning(f"检测到凭证永久失效: {filename}")
                # 记录失效状态，但不在这里禁用凭证，让上层调用者处理
                await self.record_api_call_result(filename, False, 400)
            
            return None
    
    def _is_permanent_refresh_failure(self, error_msg: str) -> bool:
        """判断是否是凭证永久失效的错误"""
        # 常见的永久失效错误模式
        permanent_error_patterns = [
            "400 Bad Request",
            "invalid_grant",
            "refresh_token_expired", 
            "invalid_refresh_token",
            "unauthorized_client",
            "access_denied"
        ]
        
        error_msg_lower = error_msg.lower()
        for pattern in permanent_error_patterns:
            if pattern.lower() in error_msg_lower:
                return True
                
        return False

    # 兼容性方法 - 保持与现有代码的接口兼容
    async def _update_token_in_file(self, file_path: str, new_token: str, expires_at=None):
        """更新凭证令牌（兼容性方法）"""
        try:
            credential_data = await self._storage_adapter.get_credential(file_path)
            if not credential_data:
                log.error(f"Credential not found for token update: {file_path}")
                return False
            
            # 更新令牌数据
            credential_data["token"] = new_token
            if expires_at:
                credential_data["expiry"] = expires_at.isoformat() if hasattr(expires_at, 'isoformat') else expires_at
            
            # 保存更新后的凭证
            success = await self._storage_adapter.store_credential(file_path, credential_data)
            
            if success:
                log.debug(f"Token updated for credential: {file_path}")
            else:
                log.error(f"Failed to update token for credential: {file_path}")
            
            return success
            
        except Exception as e:
            log.error(f"Error updating token for {file_path}: {e}")
            return False


# 全局实例管理（保持兼容性）
_credential_manager: Optional[CredentialManager] = None

async def get_credential_manager() -> CredentialManager:
    """获取全局凭证管理器实例"""
    global _credential_manager
    
    if _credential_manager is None:
        _credential_manager = CredentialManager()
        await _credential_manager.initialize()
    
    return _credential_manager