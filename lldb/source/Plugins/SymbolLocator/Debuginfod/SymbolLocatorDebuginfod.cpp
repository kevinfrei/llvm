//===-- SymbolLocatorDebuginfod.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SymbolLocatorDebuginfod.h"

#include "lldb/Core/PluginManager.h"
#include "lldb/Interpreter/OptionValueString.h"
#include "lldb/Utility/Args.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"

#include "llvm/Debuginfod/Debuginfod.h"
#include "llvm/Debuginfod/HTTPClient.h"

using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(SymbolLocatorDebuginfod)

enum SymbolLookupMode {
  eLookupModeDisabled,
  eLookupModeOnDemand,
  eLookupModeAlways,
};

static constexpr OptionEnumValueElement g_debuginfod_symbol_lookup_mode[] = {
    {
        eLookupModeDisabled,
        "disabled",
        "Do not query DEBUGINFOD servers for symbols. Cached symbols are still "
        "used. To fully disable any use of symbols located using DEBUGINFOD, "
        "set symbols.enable-external-lookup to false.",
    },
    {
        eLookupModeOnDemand,
        "on-demand",
        "Only query DEBUGINFOD servers when they're explicitly requested via "
        "commands (such as 'target symbols add' or 'target modules add') or "
        "when they're requested asynchronously (if "
        "symbols.enable-background-lookup is set). Any cached symbols "
        "previously acquired are still used.",
    },
    {
        eLookupModeAlways,
        "always",
        "Always try to find debug information for any executable or shared "
        "library in any debug session as the shared libraries are loaded. Note "
        "that this can cause a lot of debug information to appear in your "
        "project and may slow down your debug session.",
    },
};

namespace {

#define LLDB_PROPERTIES_symbollocatordebuginfod
#include "SymbolLocatorDebuginfodProperties.inc"

enum {
#define LLDB_PROPERTIES_symbollocatordebuginfod
#include "SymbolLocatorDebuginfodPropertiesEnum.inc"
};

class PluginProperties : public Properties {
public:
  static llvm::StringRef GetSettingName() {
    return SymbolLocatorDebuginfod::GetPluginNameStatic();
  }

  PluginProperties() {
    m_collection_sp = std::make_shared<OptionValueProperties>(GetSettingName());
    m_collection_sp->Initialize(g_symbollocatordebuginfod_properties);

    // We need to read the default value first to read the environment variable.
    llvm::SmallVector<llvm::StringRef> urls = llvm::getDefaultDebuginfodUrls();
    Args arg_urls{urls};
    m_collection_sp->SetPropertyAtIndexFromArgs(ePropertyServerURLs, arg_urls);

    m_collection_sp->SetValueChangedCallback(
        ePropertyServerURLs, [this] { ServerURLsChangedCallback(); });
  }

  Args GetDebugInfoDURLs() const {
    Args urls;
    m_collection_sp->GetPropertyAtIndexAsArgs(ePropertyServerURLs, urls);
    return urls;
  }

  SymbolLookupMode GetLookupMode() const {
    uint32_t idx = ePropertyEnableAutoLookup;
    return GetPropertyAtIndexAs<SymbolLookupMode>(
        idx, static_cast<SymbolLookupMode>(
                 g_debuginfod_symbol_lookup_mode[idx].value));
  }

  llvm::Expected<std::string> GetCachePath() {
    OptionValueString *s =
        m_collection_sp->GetPropertyAtIndexAsOptionValueString(
            ePropertySymbolCachePath);
    // If we don't have a valid cache location, use the default one.
    if (!s || !s->GetCurrentValueAsRef().size()) {
      llvm::Expected<std::string> maybeCachePath =
          llvm::getDefaultDebuginfodCacheDirectory();
      if (!maybeCachePath)
        return maybeCachePath;
      return *maybeCachePath;
    }
    return s->GetCurrentValue();
  }

  std::chrono::milliseconds GetTimeout() const {
    std::optional<uint64_t> seconds =
        m_collection_sp->GetPropertyAtIndexAs<uint64_t>(ePropertyTimeout);
    if (seconds && *seconds != 0) {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::seconds(*seconds));
    } else {
      return llvm::getDefaultDebuginfodTimeout();
    }
  }

private:
  void ServerURLsChangedCallback() {
    m_server_urls = GetDebugInfoDURLs();
    llvm::SmallVector<llvm::StringRef> dbginfod_urls;
    llvm::for_each(m_server_urls, [&](const auto &obj) {
      dbginfod_urls.push_back(obj.ref());
    });
    // Something's changed: reset the background attempts counter
    SymbolLocator::ResetDownloadAttempts();
    llvm::setDefaultDebuginfodUrls(dbginfod_urls);
  }
  // Storage for the StringRef's used within the Debuginfod library.
  Args m_server_urls;
};

} // namespace

static PluginProperties &GetGlobalPluginProperties() {
  static PluginProperties g_settings;
  return g_settings;
}

SymbolLocatorDebuginfod::SymbolLocatorDebuginfod() : SymbolLocator() {}

void SymbolLocatorDebuginfod::Initialize() {
  static llvm::once_flag g_once_flag;

  llvm::call_once(g_once_flag, []() {
    PluginManager::RegisterPlugin(
        GetPluginNameStatic(), GetPluginDescriptionStatic(), CreateInstance,
        LocateExecutableObjectFile, LocateExecutableSymbolFile,
        DownloadObjectAndSymbolFile, nullptr,
        SymbolLocatorDebuginfod::DebuggerInitialize);
    llvm::HTTPClient::initialize();
  });
}

void SymbolLocatorDebuginfod::DebuggerInitialize(Debugger &debugger) {
  if (!PluginManager::GetSettingForSymbolLocatorPlugin(
          debugger, PluginProperties::GetSettingName())) {
    const bool is_global_setting = true;
    PluginManager::CreateSettingForSymbolLocatorPlugin(
        debugger, GetGlobalPluginProperties().GetValueProperties(),
        "Properties for the Debuginfod Symbol Locator plug-in.",
        is_global_setting);
  }
}

void SymbolLocatorDebuginfod::Terminate() {
  PluginManager::UnregisterPlugin(CreateInstance);
  llvm::HTTPClient::cleanup();
}

llvm::StringRef SymbolLocatorDebuginfod::GetPluginDescriptionStatic() {
  return "Debuginfod symbol locator.";
}

SymbolLocator *SymbolLocatorDebuginfod::CreateInstance() {
  return new SymbolLocatorDebuginfod();
}

static std::optional<FileSpec>
GetFileForModule(const ModuleSpec &module_spec,
                 std::function<std::string(llvm::object::BuildID)> url_builder,
                 bool sync_lookup) {
  const UUID &module_uuid = module_spec.GetUUID();
  // Quit early if we don't have a valid UUID or if Debuginfod doesn't work.
  if (!module_uuid.IsValid() || !llvm::canUseDebuginfod())
    return {};

  // Grab LLDB's Debuginfod overrides from the
  // plugin.symbol-locator.debuginfod.* settings.
  PluginProperties &plugin_props = GetGlobalPluginProperties();
  llvm::Expected<std::string> cache_path_or_err = plugin_props.GetCachePath();
  // A cache location is *required*.
  if (!cache_path_or_err)
    return {};
  std::string cache_path = *cache_path_or_err;
  llvm::SmallVector<llvm::StringRef> debuginfod_urls =
      llvm::getDefaultDebuginfodUrls();
  std::chrono::milliseconds timeout = plugin_props.GetTimeout();
  // sync_lookup is also 'force_lookup' which overrides the global setting
  if (!sync_lookup &&
      !ModuleList::GetGlobalModuleListProperties().GetEnableExternalLookup())
    return {};

  // We're ready to ask the Debuginfod library to find our file.
  llvm::object::BuildID build_id(module_uuid.GetBytes());
  std::string url_path = url_builder(build_id);
  std::string cache_key = llvm::getDebuginfodCacheKey(url_path);
  bool ask_server = sync_lookup || plugin_props.GetLookupMode() ==
                                       SymbolLookupMode::eLookupModeAlways;
  llvm::Expected<std::string> result =
      ask_server
          ? llvm::getCachedOrDownloadArtifact(cache_key, url_path, cache_path,
                                              debuginfod_urls, timeout)
          : llvm::getCachedArtifact(cache_key, cache_path);
  if (result)
    return FileSpec(*result);
  if (!ask_server)
    // If we only checked the cache & failed, query the server asynchronously.
    // This API only requests the symbols if the user has enabled the
    // 'symbol.enable-background-lookup' setting.
    SymbolLocator::DownloadSymbolFileAsync(module_uuid);
  else {
    Log *log = GetLog(LLDBLog::Symbols);
    auto err_message = llvm::toString(result.takeError());
    LLDB_LOGV(
        log, "Debuginfod failed to download symbol artifact {0} with error {1}",
        url_path, err_message);
  }
  return {};
}

std::optional<ModuleSpec> SymbolLocatorDebuginfod::LocateExecutableObjectFile(
    const ModuleSpec &module_spec) {
  return GetFileForModule(module_spec, llvm::getDebuginfodExecutableUrlPath,
                          false);
}

std::optional<FileSpec> SymbolLocatorDebuginfod::LocateExecutableSymbolFile(
    const ModuleSpec &module_spec, const FileSpecList &default_search_paths) {
  return GetFileForModule(module_spec, llvm::getDebuginfodDebuginfoUrlPath,
                          false);
}

// This API is only used asynchronously, or when the user explicitly asks for
// symbols via target symbols add
bool SymbolLocatorDebuginfod::DownloadObjectAndSymbolFile(
    ModuleSpec &module_spec, Status &error, bool sync_lookup,
    bool copy_executable) {
  // copy_executable is only used for macOS kernel debugging stuff involving
  // dSYM bundles, so we're not using it here.
  const UUID *uuid_ptr = module_spec.GetUUIDPtr();
  const FileSpec *file_spec_ptr = module_spec.GetFileSpecPtr();

  // We need a UUID or valid existing FileSpec.
  if (!uuid_ptr &&
      (!file_spec_ptr || !FileSystem::Instance().Exists(*file_spec_ptr)))
    return false;

  // For DWP files, if you're running a stripped binary, you'll probably want to
  // get *both* the symbols and the executable. If your binary isn't stripped,
  // then you won't need the executable, but for now, we'll try to download
  // both.
  bool found = false;
  if (!module_spec.GetSymbolFileSpec()) {
    std::optional<FileSpec> SymbolFile = GetFileForModule(
        module_spec, llvm::getDebuginfodDebuginfoUrlPath, sync_lookup);
    if (SymbolFile) {
      module_spec.GetSymbolFileSpec() = *SymbolFile;
      found = true;
    }
  }

  if (!module_spec.GetFileSpec()) {
    std::optional<FileSpec> ExecutableFile = GetFileForModule(
        module_spec, llvm::getDebuginfodExecutableUrlPath, sync_lookup);
    if (ExecutableFile) {
      module_spec.GetFileSpec() = *ExecutableFile;
      found = true;
    }
  }
  return found;
}
