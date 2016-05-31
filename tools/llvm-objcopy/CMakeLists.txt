set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  Core
  Object
  Support
  )

add_llvm_tool(llvm-objcopy
  ELFCopier.cpp
  Objopier.cpp
  llvm-objcopy.cpp
  )
