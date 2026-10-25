# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
"""Public model facade.

The implementation is organized by domain. Re-exporting the established names
here keeps callers independent of that internal layout.
"""

from shepherd_scan._vendor.discovery.models.api import *  # noqa: F403
from shepherd_scan._vendor.discovery.models.api import __all__ as _api_models
from shepherd_scan._vendor.discovery.models.errors import (
    FAILURE_CATEGORY_TO_CODE,
    AnalysisError,
    CouldNotParseMCPConfig,
    ErrorCategory,
    FileNotFoundConfig,
    ScanError,
    SerializedException,
    ServerHTTPError,
    ServerStartupError,
    SkillScanError,
    UnknownConfigFormat,
    UserDeclinedError,
)
from shepherd_scan._vendor.discovery.models.inspect import (
    CandidateClient,
    ClientToInspect,
    InspectedPath,
    InspectedServer,
    InspectedSkill,
)
from shepherd_scan._vendor.discovery.models.mcp import (
    SERVER_CONFIG_DISCRIMINATOR_KEYS,
    ClaudeCodeConfigFile,
    ClaudeConfigFile,
    CommandParsingError,
    ConfigWithoutMCP,
    Entity,
    MCPConfig,
    MCPServerMap,
    Metadata,
    OpenCodeConfigFile,
    PluginMCPConfigFile,
    RemoteServer,
    ServerSignature,
    StartMCPServerError,
    StdioServer,
    UnknownMCPConfig,
    VSCodeConfigFile,
    VSCodeMCPConfig,
    entity_to_tool,
    rebalance_command_args,
)
from shepherd_scan._vendor.discovery.models.push import (
    ControlServer,
    FileTokenStorage,
    TokenAndClientInfo,
    TokenAndClientInfoList,
)
from shepherd_scan._vendor.discovery.models.skill import DiscoveredSkill, SkillFile

__all__ = [
    *_api_models,
    "FAILURE_CATEGORY_TO_CODE",
    "SERVER_CONFIG_DISCRIMINATOR_KEYS",
    "AnalysisError",
    "CandidateClient",
    "ClaudeCodeConfigFile",
    "ClaudeConfigFile",
    "ClientToInspect",
    "CommandParsingError",
    "ConfigWithoutMCP",
    "ControlServer",
    "CouldNotParseMCPConfig",
    "DiscoveredSkill",
    "Entity",
    "ErrorCategory",
    "FileNotFoundConfig",
    "FileTokenStorage",
    "InspectedPath",
    "InspectedServer",
    "InspectedSkill",
    "MCPConfig",
    "MCPServerMap",
    "Metadata",
    "OpenCodeConfigFile",
    "PluginMCPConfigFile",
    "RemoteServer",
    "ScanError",
    "SerializedException",
    "ServerHTTPError",
    "ServerSignature",
    "ServerStartupError",
    "SkillFile",
    "SkillScanError",
    "StartMCPServerError",
    "StdioServer",
    "TokenAndClientInfo",
    "TokenAndClientInfoList",
    "UnknownConfigFormat",
    "UnknownMCPConfig",
    "UserDeclinedError",
    "VSCodeConfigFile",
    "VSCodeMCPConfig",
    "entity_to_tool",
    "rebalance_command_args",
]
