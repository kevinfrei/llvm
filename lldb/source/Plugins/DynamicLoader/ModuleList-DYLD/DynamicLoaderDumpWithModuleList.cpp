//===-- DynamicLoaderDumpWithModuleList.cpp-------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// Main header include
#include "DynamicLoaderDumpWithModuleList.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Target/Process.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"

#include "Plugins/ObjectFile/Placeholder/ObjectFilePlaceholder.h"

using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE_ADV(DynamicLoaderDumpWithModuleList,
                       DynamicLoaderDumpWithModuleList)

void DynamicLoaderDumpWithModuleList::Initialize() {
  PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                GetPluginDescriptionStatic(), CreateInstance);
}

void DynamicLoaderDumpWithModuleList::Terminate() {}

llvm::StringRef DynamicLoaderDumpWithModuleList::GetPluginDescriptionStatic() {
  return "Dynamic loader plug-in for dumps with module list available";
}

DynamicLoader *DynamicLoaderDumpWithModuleList::CreateInstance(Process *process,
                                                               bool force) {
  // This plug-in is only used when it is requested by name from
  // ProcessELFCore. ProcessELFCore will look to see if the core
  // file contains a NT_FILE ELF note, and ask for this plug-in
  // by name if it does.
  if (force)
    return new DynamicLoaderDumpWithModuleList(process);
  return nullptr;
}

DynamicLoaderDumpWithModuleList::DynamicLoaderDumpWithModuleList(
    Process *process)
    : DynamicLoader(process), m_rendezvous(process), m_auxv(),
      m_vdso_base(LLDB_INVALID_ADDRESS) {}

DynamicLoaderDumpWithModuleList::~DynamicLoaderDumpWithModuleList() {}

std::optional<const LoadedModuleInfoList::LoadedModuleInfo>
DynamicLoaderDumpWithModuleList::GetModuleInfo(lldb::addr_t module_base_addr) {
  if (m_module_addr_to_info_map.empty()) {
    llvm::Expected<LoadedModuleInfoList> module_info_list_ep =
        m_process->GetLoadedModuleList();
    if (!module_info_list_ep)
      return std::nullopt;

    const LoadedModuleInfoList &module_info_list = *module_info_list_ep;
    if (module_info_list.m_list.empty())
      return std::nullopt;

    for (const LoadedModuleInfoList::LoadedModuleInfo &mod_info :
         module_info_list.m_list) {
      lldb::addr_t base_addr;
      if (!mod_info.get_base(base_addr))
        continue;
      m_module_addr_to_info_map.emplace(base_addr, mod_info);
    }
  }

  auto module_match_iter = m_module_addr_to_info_map.find(module_base_addr);
  if (module_match_iter == m_module_addr_to_info_map.end())
    return std::nullopt;

  return module_match_iter->second;
}

void DynamicLoaderDumpWithModuleList::DetectModuleListMismatch() {
  llvm::Expected<LoadedModuleInfoList> module_info_list_ep =
      m_process->GetLoadedModuleList();
  if (!module_info_list_ep || (*module_info_list_ep).m_list.empty())
    return;

  DYLDRendezvous::iterator I;
  DYLDRendezvous::iterator E;
  uint32_t mismatched_module_count = 0;

  Log *log = GetLog(LLDBLog::DynamicLoader);
  assert(m_rendezvous.IsValid() && "m_rendezvous is not resolved yet.");
  for (I = m_rendezvous.begin(), E = m_rendezvous.end(); I != E; ++I) {
    // vdso is an in-memory module which won't be in loaded module list.
    if (I->base_addr == m_vdso_base)
      continue;

    std::optional<const LoadedModuleInfoList::LoadedModuleInfo> mod_info_opt =
        GetModuleInfo(I->base_addr);
    if (!mod_info_opt.has_value()) {
      ++mismatched_module_count;

      LLDB_LOGF(
          log,
          "DynamicLoaderDumpWithModuleList::%s found mismatch module %s at "
          "rendezvous address 0x%lx",
          __FUNCTION__, I->file_spec.GetPath().c_str(), I->base_addr);
    }
  }
  m_process->GetTarget().GetStatistics().SetMismatchedCoredumpModuleCount(
      mismatched_module_count);
}

void DynamicLoaderDumpWithModuleList::LoadAllModules(
    LoadModuleCallback callback) {

  if (m_rendezvous.Resolve()) {
    DYLDRendezvous::iterator I;
    DYLDRendezvous::iterator E;
    for (I = m_rendezvous.begin(), E = m_rendezvous.end(); I != E; ++I) {
      // Module size has to be > 0 to be valid.
      addr_t module_size = 1;
      std::optional<const LoadedModuleInfoList::LoadedModuleInfo> mod_info_opt =
          GetModuleInfo(I->base_addr);
      if (mod_info_opt.has_value())
        (*mod_info_opt).get_size(module_size);
      callback(I->file_spec.GetPath(), I->base_addr, module_size);
    }

    DetectModuleListMismatch();
  } else {
    Log *log = GetLog(LLDBLog::DynamicLoader);
    LLDB_LOGF(
        log,
        "DynamicLoaderDumpWithModuleList::%s unable to resolve POSIX DYLD "
        "rendezvous address. Fallback to try GetLoadedModuleList().",
        __FUNCTION__);

    llvm::Expected<LoadedModuleInfoList> module_info_list_ep =
        m_process->GetLoadedModuleList();
    if (!module_info_list_ep) {
      LLDB_LOGF(log,
                "DynamicLoaderDumpWithModuleList::%s fail to get module list "
                "from GetLoadedModuleList().",
                __FUNCTION__);
      llvm::consumeError(module_info_list_ep.takeError());
      return;
    }

    const LoadedModuleInfoList &module_info_list = *module_info_list_ep;
    for (const LoadedModuleInfoList::LoadedModuleInfo &mod_info :
         module_info_list.m_list) {
      addr_t base_addr, module_size;
      std::string name;
      if (!mod_info.get_base(base_addr) || !mod_info.get_name(name) ||
          !mod_info.get_size(module_size))
        continue;

      callback(name, base_addr, module_size);
    }
  }
}

void DynamicLoaderDumpWithModuleList::DidAttach() {
  Log *log = GetLog(LLDBLog::DynamicLoader);
  LLDB_LOGF(log, "DynamicLoaderDumpWithModuleList::%s() pid %" PRIu64,
            __FUNCTION__,
            m_process ? m_process->GetID() : LLDB_INVALID_PROCESS_ID);
  m_auxv = std::make_unique<AuxVector>(m_process->GetAuxvData());

  ModuleSP executable_sp = GetTargetExecutable();
  if (executable_sp) {
    m_rendezvous.UpdateExecutablePath();
    UpdateLoadedSections(executable_sp, LLDB_INVALID_ADDRESS, /*load_offset=*/0,
                         true);
  }
  EvalSpecialModulesStatus();
  LoadVDSO();

  ModuleList module_list;
  LoadAllModules([&](const std::string &name, addr_t base_addr,
                     addr_t module_size) {
    // vdso module has already been loaded.
    if (base_addr == m_vdso_base)
      return;

    addr_t link_map_addr = 0;
    FileSpec file(name, m_process->GetTarget().GetArchitecture().GetTriple());
    const bool base_addr_is_offset = false;
    ModuleSP module_sp = DynamicLoader::LoadModuleAtAddress(
        file, link_map_addr, base_addr, base_addr_is_offset);
    if (module_sp.get()) {
      LLDB_LOGF(log, "LoadAllCurrentModules loading module at 0x%lX: %s",
                base_addr, name.c_str());
      module_list.Append(module_sp);
    } else {
      LLDB_LOGF(
          log,
          "DynamicLoaderDumpWithModuleList::%s unable to locate the matching "
          "object file %s, creating a placeholder module at 0x%" PRIx64,
          __FUNCTION__, name.c_str(), base_addr);

      ModuleSpec module_spec(file, m_process->GetTarget().GetArchitecture());
      module_sp = Module::CreateModuleFromObjectFile<ObjectFilePlaceholder>(
          module_spec, base_addr, module_size);
      UpdateLoadedSections(module_sp, link_map_addr, base_addr,
                           base_addr_is_offset);
      m_process->GetTarget().GetImages().Append(module_sp, /*notify*/ true);
    }
  });

  m_process->GetTarget().ModulesDidLoad(module_list);
}

void DynamicLoaderDumpWithModuleList::EvalSpecialModulesStatus() {
  if (std::optional<uint64_t> vdso_base =
          m_auxv->GetAuxValue(AuxVector::AUXV_AT_SYSINFO_EHDR))
    m_vdso_base = *vdso_base;
}

void DynamicLoaderDumpWithModuleList::LoadVDSO() {
  if (m_vdso_base == LLDB_INVALID_ADDRESS)
    return;

  Log *log = GetLog(LLDBLog::DynamicLoader);
  LLDB_LOGF(log, "Loading vdso at 0x%lx", m_vdso_base);

  MemoryRegionInfo info;
  Status status = m_process->GetMemoryRegionInfo(m_vdso_base, info);
  if (status.Fail()) {
    LLDB_LOG(log, "Failed to get vdso region info: {0}", status);
    return;
  }

  FileSpec file("[vdso]");
  if (ModuleSP module_sp = m_process->ReadModuleFromMemory(
          file, m_vdso_base, info.GetRange().GetByteSize())) {
    UpdateLoadedSections(module_sp, LLDB_INVALID_ADDRESS, m_vdso_base, false);
    m_process->GetTarget().GetImages().AppendIfNeeded(module_sp);
  }
}

lldb_private::Status DynamicLoaderDumpWithModuleList::CanLoadImage() {
  return Status();
}
