"""A1 执行 Agent（变体生成）。

边界（设计文档 §1）：只负责"把变体造出来、摆整齐"——读计划、展开配方、
调 builder/isolator 造变体、完整性自检、按分数挑 V2、交付预注册 V3。
不做：判分（评估 Agent）、跑功能一致性（监管 Agent 组织）、改判定规则（谁都不许）、
改 C 源码（谁都不许）、写报告正文（评估 Agent）。

模块：plan（计划/状态） expand（模板展开） generate（构建编排）
     verify（完整性自检） select（V2 初筛） deliver（交付）。
"""
