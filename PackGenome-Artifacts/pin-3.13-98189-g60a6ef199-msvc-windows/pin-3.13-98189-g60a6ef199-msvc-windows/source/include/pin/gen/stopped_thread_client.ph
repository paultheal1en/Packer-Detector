//Groups: @ingroup\s+(API_REF|KNOBS|IMG_BASIC_API|INS_BASIC_API|INS_INST_API|INS_BASIC_API_GEN_IA32|INS_BASIC_API_IA32|INS_MOD_API_GEN_IA32|SEC_BASIC_API|RTN_BASIC_API|REG_BASIC_API|REG_CPU_GENERIC|REG_CPU_IA32|TRACE_BASIC_API|BBL_BASIC_API|SYM_BASIC_API|MISC_PRINT|MISC_PARSE|KNOB_API|KNOB_BASIC|KNOB_PRINT|LOCK|PIN_CONTROL|TRACE_VERSION_API|BUFFER_API|PROTO_API|PIN_PROCESS_API|PIN_THREAD_API|PIN_SYSCALL_API|WINDOWS_SYSCALL_API_UNDOC|DEBUG_API|ERROR_FILE_BASIC|TYPE_BASE|INSTLIB|ALARM|CHILD_PROCESS_API|UTILS|MISC|CONTEXT_API|PHYSICAL_CONTEXT_API|PIN_CALLBACKS|EXCEPTION_API|APPDEBUG_API|STOPPED_THREAD_API|BUFFER_API|PROTO|INST_ARGS|DEPRECATED_PIN_API|INTERNAL_EXCEPTION_PRIVATE_UNDOCUMENTED|PIN_THREAD_PRIVATE|CHILD_PROCESS_INTERNAL|BBL_BASIC|ROGUE_BASIC_API|MESSAGE_TYPE|MESSAGE_BASIC|ERRFILE|MISC_BASIC|ITC_INST_API|CONTEXT_API_UNDOC|EXCEPTION_API_UNDOC|UNDOCUMENTED_PIN_API|OPIN|TRACE_VERSIONS
/* PIN API */

/* THIS FILE IS AUTOMAGICALLY GENERATED - DO NOT CHANGE DIRECTLY*/


extern BOOL PIN_StopApplicationThreads(THREADID tid);

                                                                  /* DO NOT EDIT */
extern BOOL PIN_IsThreadStoppedInDebugger(THREADID tid);

                                                                  /* DO NOT EDIT */
extern VOID PIN_ResumeApplicationThreads(THREADID tid);

                                                                  /* DO NOT EDIT */
extern UINT32 PIN_GetStoppedThreadCount();

                                                                  /* DO NOT EDIT */
extern THREADID PIN_GetStoppedThreadId(UINT32 i);

                                                                  /* DO NOT EDIT */
extern const CONTEXT *PIN_GetStoppedThreadContext(THREADID tid);

                                                                  /* DO NOT EDIT */
extern CONTEXT *PIN_GetStoppedThreadWriteableContext(THREADID tid);

                                                                  /* DO NOT EDIT */

