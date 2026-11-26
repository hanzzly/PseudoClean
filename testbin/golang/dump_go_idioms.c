// === runtime.main.func2 @ 0x44bc20 ===
// runtime.main.func2
_BYTE *__golang runtime_main_func2()
{
  __int64 v0; // rdx
  _BYTE *result; // rax

  result = *(_BYTE **)(v0 + 8);
  if ( *result != 0 )
    return (_BYTE *)runtime_unlockOSThread();
  return result;
}


// === runtime.main.func1 @ 0x478a00 ===
// runtime.main.func1
__int64 runtime_main_func1()
{
  return runtime_newm(off_50CD50, 0, -1);
}


// === main.idiomStringSlice @ 0x4c2e20 ===
// main.idiomStringSlice
__int64 __golang main_idiomStringSlice(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 v3; // rbx
  __int64 v4; // rax
  _BYTE *r0; // rax
  _BYTE v7[32]; // [rsp+58h] [rbp-98h] BYREF
  _BYTE v8[8]; // [rsp+78h] [rbp-78h] BYREF
  _BYTE v9[32]; // [rsp+98h] [rbp-58h] BYREF
  __int64 r1; // [rsp+B8h] [rbp-38h]
  _BYTE v11[32]; // [rsp+C0h] [rbp-30h] BYREF
  __int64 v12; // [rsp+E0h] [rbp-10h]
  int v13; // [rsp+F8h] [rbp+8h]
  int v14; // [rsp+100h] [rbp+10h]
  retval_465780 v15; // 0:kr20_16.16
  retval_4651C0 v16; // 0:kr30_16.16
  retval_465940 v17; // 0:kr00_24.24

  v14 = a2;
  v13 = a1;
  v17 = runtime_stringtoslicebyte(v9, a1, a2);
  r0 = (_BYTE *)v17._r0;
  v2 = v17._r1 + 4LL;
  if ( v17._r2 < (unsigned __int64)(v17._r1 + 4LL) )
  {
    if ( v2 > 32 || v17._r1 != 0 )
    {
      r0 = (_BYTE *)runtime_growslice(4, &RTYPE_uint8);
      v2 = v3;
    }
    else
    {
      r0 = v11;
      memset(v11, 0, sizeof(v11));
    }
  }
  *(_DWORD *)&r0[v2 - 4] = 1111572257;
  v15 = runtime_slicebytetostring(v8, r0, v2);
  v12 = v15._r0;
  r1 = v15._r1;
  v16 = runtime_concatstring2(v7, v15._r0, v15._r1, "_suffix", 7);
  v4 = runtime_concatstring5(
         0,
         v13,
         v14,
         (unsigned int)&unk_50CE48,
         1,
         v12,
         r1,
         (unsigned int)&unk_50CE48,
         1,
         v16._r0,
         v16._r1);
  return strings_TrimSpace(v4);
}


// === main.idiomFileCLI @ 0x4c2f60 ===
// main.idiomFileCLI
retval_4C2F60 __golang main_idiomFileCLI(__int64 a1, __int64 a2)
{
  unsigned __int64 r2; // rax
  __int64 r1; // rcx
  __int64 i; // rbx
  __int64 v8; // rdi
  __int64 v9; // rdx
  __int64 v10; // rbx
  __int64 v11; // r8
  unsigned __int64 v12; // rcx
  __int64 v13; // rax
  __int64 len; // rdi
  __int64 v15; // rcx
  unsigned __int64 v16; // rbx
  uint8 *str; // rsi
  unsigned __int64 v18; // rdx
  __int64 v19; // rax
  unsigned __int64 v20; // rcx
  __int64 v21; // rax
  __int64 v23; // [rsp+2h] [rbp-118h]
  __int64 v24; // [rsp+Ah] [rbp-110h]
  __int64 v25; // [rsp+Ah] [rbp-110h]
  unsigned __int64 v26; // [rsp+Ah] [rbp-110h]
  unsigned __int64 v27; // [rsp+12h] [rbp-108h]
  unsigned __int64 v28; // [rsp+12h] [rbp-108h]
  unsigned __int64 v29; // [rsp+12h] [rbp-108h]
  __int64 v30; // [rsp+1Ah] [rbp-100h]
  __int64 v31; // [rsp+32h] [rbp-E8h]
  __int64 v32; // [rsp+52h] [rbp-C8h]
  __int64 v33; // [rsp+52h] [rbp-C8h]
  __int64 v34; // [rsp+52h] [rbp-C8h]
  uint8 *v35; // [rsp+5Ah] [rbp-C0h]
  _QWORD v36[2]; // [rsp+62h] [rbp-B8h] BYREF
  _QWORD v37[4]; // [rsp+72h] [rbp-A8h] BYREF
  __int128 v38; // [rsp+92h] [rbp-88h]
  __int128 v39; // [rsp+A2h] [rbp-78h]
  __int128 v40; // [rsp+B2h] [rbp-68h]
  __int128 v41; // [rsp+C2h] [rbp-58h]
  __int128 v42; // [rsp+D2h] [rbp-48h]
  __int128 v43; // [rsp+E2h] [rbp-38h]
  _QWORD v44[2]; // [rsp+F2h] [rbp-28h] BYREF
  string *p_string; // [rsp+102h] [rbp-18h]
  void (__golang **v46)(__int64); // [rsp+10Ah] [rbp-10h]
  errors_errorString *p_errors_errorString; // 0:rax.8
  retval_4A26A0 v49; // 0:kr00_24.24
  retval_4A2980 File; // 0:kr20_40.40
  retval_4C2F60 result; // 0:rax.8,8:rbx.8,16:rcx.8,24:rdi.16

  v46 = nullptr;
  if ( a2 < 2 )
  {
    p_errors_errorString = (errors_errorString *)runtime_newobject(&RTYPE_errors_errorString);
    p_errors_errorString->s.len = 25;
    p_errors_errorString->s.str = (uint8 *)"path file tidak diberikan";
    result._r3 = go_itab__ptr_errors_errorString_comma__ptr_error;
    result._r1 = 0;
    result._r4 = p_errors_errorString;
    result._r0 = 0;
    result._r2 = 0;
  }
  else
  {
    File = os_ReadFile(*(_QWORD *)(a1 + 16), *(_QWORD *)(a1 + 24));
    *(_OWORD *)&result._r3 = *(_OWORD *)&File._r3;
    if ( File._r3 != 0 )
    {
      result._r0 = 0;
      result._r2 = 0;
      result._r1 = 0;
    }
    else
    {
      v49 = os_OpenFile(*(_QWORD *)(a1 + 16), *(_QWORD *)(a1 + 24), 0, 0, File._r4);
      if ( v49._r1 != 0 )
      {
        result._r0 = 0;
        *(_OWORD *)&result._r3 = *(_OWORD *)&v49._r1;
        result._r2 = 0;
        result._r1 = 0;
      }
      else
      {
        v44[0] = main_idiomFileCLI_deferwrap1;
        v44[1] = v49._r0;
        v46 = (void (__golang **)(__int64))v44;
        v38 = 0;
        v39 = 0;
        v40 = 0;
        v41 = 0;
        v42 = 0;
        v43 = 0;
        v37[0] = go_itab__ptr_os_File_comma__ptr_io_Reader;
        v37[1] = v49._r0;
        v37[2] = off_50C840;
        v37[3] = 0x10000;
        r2 = File._r2;
        r1 = File._r1;
        for ( i = File._r0; ; i = v32 )
        {
          v33 = i;
          v28 = r2;
          v25 = r1;
          if ( (unsigned __int8)bufio__ptr_Scanner_Scan(v37) == 0 )
            break;
          v8 = *((_QWORD *)&v38 + 1);
          v9 = v25;
          v10 = *((_QWORD *)&v38 + 1) + v25;
          v11 = v38;
          v12 = v28;
          if ( v28 < *((_QWORD *)&v38 + 1) + v25 )
          {
            v23 = *((_QWORD *)&v38 + 1);
            v31 = v38;
            v13 = runtime_growslice(*((_QWORD *)&v38 + 1), &RTYPE_uint8);
            v9 = v25;
            v8 = v23;
            v11 = v31;
          }
          else
          {
            v13 = v33;
          }
          v27 = v12;
          v24 = v10;
          v32 = v13;
          runtime_memmove(v9 + v13, v11, v8);
          r2 = v27;
          r1 = v24;
        }
        p_string = (string *)runtime_newobject(&RTYPE_string);
        v36[0] = &RTYPE__ptr_string;
        v36[1] = p_string;
        fmt_Fscanln(go_itab__ptr_os_File_comma__ptr_io_Reader, qword_5EFB80, v36, 1, 1);
        len = p_string->len;
        v15 = v25;
        v16 = len + v25;
        str = (uint8 *)&unk_610260;
        if ( p_string->str != nullptr )
          str = p_string->str;
        v18 = v28;
        if ( v28 < v16 )
        {
          v30 = p_string->len;
          v35 = str;
          v19 = runtime_growslice(len, &RTYPE_uint8);
          str = v35;
          len = v30;
          v18 = v20;
          v15 = v25;
        }
        else
        {
          v19 = v33;
        }
        v29 = v18;
        v26 = v16;
        v34 = v19;
        v21 = runtime_memmove(v15 + v19, str, len);
        (*v46)(v21);
        *(_OWORD *)&result._r3 = 0;
        result._r0 = v34;
        result._r2 = v29;
        result._r1 = v26;
      }
    }
  }
  return result;
}


// === main.idiomFileCLI.deferwrap1 @ 0x4c33e0 ===
// main.idiomFileCLI.deferwrap1
retval_4C33E0 __golang main_idiomFileCLI_deferwrap1()
{
  __int64 v0; // rdx
  _ptr_os_file *v1; // rcx
  error v4; // 0:kr00_16.16
  retval_4C33E0 result; // 0:rax.8,8:rbx.8

  v1 = *(_ptr_os_file **)(v0 + 8);
  if ( v1 != nullptr )
  {
    v4 = os__ptr_file_close(*v1);
    result._r0 = v4.tab;
    result._r1 = v4.data;
  }
  return result;
}


// === main.idiomControlFlow @ 0x4c3420 ===
// main.idiomControlFlow
retval_4C3420 __golang main_idiomControlFlow(__int64 a1, unsigned __int64 a2, __int64 a3, __int64 a4)
{
  unsigned __int8 v7; // [rsp+0h] [rbp-32h]
  __int128 v8; // [rsp+2h] [rbp-30h] BYREF
  _QWORD v9[2]; // [rsp+12h] [rbp-20h] BYREF
  void (**v10)(void); // [rsp+22h] [rbp-10h]
  retval_4C3420 result; // 0:rax.8,8:rbx.8,16:rcx.8

  v8 = 0;
  v9[0] = main_idiomControlFlow_func1;
  v9[1] = &v8;
  v10 = (void (**)(void))v9;
  if ( a4 < 0 )
    runtime_gopanic(&RTYPE_string, &sIndeksTidakBol);
  if ( a2 <= a4 )
    runtime_panicBounds();
  v7 = *(_BYTE *)(a1 + a4);
  if ( a4 == 0 )
    runtime_panicBounds();
  if ( a4 != 1 )
    v7 = *(_BYTE *)(a1 + 1) ^ *(_BYTE *)(a1 + a4);
  v8 = 0;
  (*v10)();
  result._r0 = v7;
  result._r2 = *((_QWORD *)&v8 + 1);
  result._r1 = v8;
  return result;
}


// === main.idiomControlFlow.func1 @ 0x4c3540 ===
// main.idiomControlFlow.func1
RTYPE **__golang main_idiomControlFlow_func1()
{
  __int64 v0; // rdx
  errors_errorString *r1; // rbx
  RTYPE ***r2; // rcx
  RTYPE **result; // rax
  retval_447E40 v4; // [rsp+0h] [rbp-20h] BYREF
  RTYPE ***v5; // [rsp+10h] [rbp-10h]
  errors_errorString *p_errors_errorString; // 0:rax.8
  retval_447E40 v7; // 0:kr00_16.16
  retval_4827C0 v8; // 0:kr50_72.72

  v5 = *(RTYPE ****)(v0 + 8);
  v7 = runtime_gorecover();
  result = (RTYPE **)v7._r0;
  if ( v7._r0 != 0 )
  {
    v4 = v7;
    result = (RTYPE **)fmt_errorf("terjadi panic: %v", 17, &v4, 1, 1);
    if ( result == nullptr )
    {
      p_errors_errorString = (errors_errorString *)runtime_newobject(&RTYPE_errors_errorString);
      p_errors_errorString->s.len = 17;
      p_errors_errorString->s.str = (uint8 *)"terjadi panic: %v";
      r1 = p_errors_errorString;
      result = go_itab__ptr_errors_errorString_comma__ptr_error;
    }
    r2 = v5;
    *v5 = result;
    if ( dword_610560 != 0 )
    {
      v8 = runtime_gcWriteBarrier2(r2[1], r1);
      result = (RTYPE **)v8._r0;
      r1 = (errors_errorString *)v8._r1;
      r2 = (RTYPE ***)v8._r2;
      *(_QWORD *)v8._r8 = v8._r1;
      *(_QWORD *)(v8._r8 + 8LL) = v8._r0;
    }
    r2[1] = (RTYPE **)r1;
  }
  return result;
}


// === main._ptr_XorProcessor.Process @ 0x4c3600 ===
// main.(*XorProcessor).Process
__int64 __golang main__ptr_XorProcessor_Process(_BYTE *a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rdx
  __int64 v4; // rsi

  v3 = 0;
  v4 = 0;
  while ( a3 > v3 )
    v4 += (unsigned __int8)(*a1 ^ *(_BYTE *)(a2 + v3++));
  return v4;
}


// === main.idiomDataStructures @ 0x4c3640 ===
// main.idiomDataStructures
__int64 __golang main_idiomDataStructures(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  _OWORD *v5; // rax
  int i; // ecx
  _QWORD *v7; // rax
  _QWORD *v8; // rcx
  __int64 v9; // rdx
  __int64 v10; // rbx
  __int64 j; // rsi
  __int64 v12; // rdx
  __int64 v13; // rsi
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rbx
  void *v17; // rdx
  __int64 v19; // [rsp+0h] [rbp-148h]
  __int64 v20; // [rsp+8h] [rbp-140h]
  __int64 v21; // [rsp+10h] [rbp-138h]
  _QWORD *v22; // [rsp+18h] [rbp-130h]
  char v23[8]; // [rsp+20h] [rbp-128h] BYREF
  const char *v24; // [rsp+28h] [rbp-120h]
  __int64 v25; // [rsp+30h] [rbp-118h]
  _QWORD v26[4]; // [rsp+38h] [rbp-110h] BYREF
  _QWORD v27[6]; // [rsp+100h] [rbp-48h] BYREF
  _QWORD v28[3]; // [rsp+130h] [rbp-18h] BYREF
  retval_411A00 v33; // 0:kr00_16.16

  memset(v27, 0, sizeof(v27));
  v5 = v26;
  for ( i = 3; i != 0; --i )
  {
    *v5 = 0;
    v5[1] = 0;
    v5[2] = 0;
    v5[3] = 0;
    v5 += 4;
  }
  *(_OWORD *)((char *)v5 - 8) = 0;
  v26[0] = 0x8080808080808080LL;
  v27[2] = v26;
  v27[1] = runtime_rand();
  v7 = a1;
  v8 = a1;
  v9 = a5;
  v10 = a2;
  for ( j = 0; v10 > j; ++j )
  {
    if ( v9 > j )
    {
      v20 = j;
      v22 = v7;
      v21 = *(_QWORD *)(a4 + 8 * j);
      *(_QWORD *)runtime_mapassign_faststr(&RTYPE_map_string_int, v27, *v7, v7[1]) = v21;
      v7 = v22;
      v8 = a1;
      v9 = a5;
      v10 = a2;
      j = v20;
    }
    v7 += 2;
  }
  if ( v10 == 0 )
    runtime_panicBounds(v7, 0, v8);
  v19 = *(_QWORD *)runtime_mapaccess1_faststr(&RTYPE_map_string_int, v27, *v8, v8[1]);
  v33 = runtime_mapaccess2_faststr(&RTYPE_map_string_int, v27, "flag_key", 8);
  v12 = *(_QWORD *)v33._r0;
  v23[0] = 90;
  v25 = 10;
  v24 = "custom_xor";
  v13 = 42;
  if ( v33._r1 != 0 )
    v13 = v12;
  v14 = runtime_convT64(v13 + v19);
  v28[0] = &RTYPE_int;
  v28[1] = v14;
  v15 = fmt_Sprintf("%v", 2, v28, 1, 1);
  v17 = &unk_610260;
  if ( v15 != 0 )
    v17 = (void *)v15;
  return main__ptr_XorProcessor_Process(v23, (__int64)v17, v16);
}


// === main.idiomConcurrency @ 0x4c38c0 ===
// main.idiomConcurrency
__int64 __golang main_idiomConcurrency(__int64 a1, __int64 a2)
{
  __int64 v2; // rcx
  $FA4B3C9BFF72A34B8428B600136518FC *r0; // rax
  __int64 v4; // rbx
  sync_WaitGroup *v5; // rcx
  chan_int *v6; // rdx
  struct__F_uintptr_X0_funcint_X1_int_ *p_struct__F_uintptr_X0_funcint_X1_int_; // rax
  void (__golang **v8)(signed __int64); // rcx
  __int64 v9; // rax
  __int64 v11; // [rsp+0h] [rbp-40h]
  signed __int64 v12; // [rsp+8h] [rbp-38h]
  __int64 v13; // [rsp+10h] [rbp-30h]
  __int64 v14; // [rsp+18h] [rbp-28h] BYREF
  chan_int *p_chan_int; // [rsp+20h] [rbp-20h]
  $FA4B3C9BFF72A34B8428B600136518FC *v16; // [rsp+28h] [rbp-18h]
  _ptr_sync_WaitGroup v17; // [rsp+30h] [rbp-10h]
  sync_WaitGroup *p_sync_WaitGroup; // 0:rax.8
  retval_4827C0 v21; // 0:kr40_72.72
  retval_4827A0 v22; // 0:krC8_72.72

  p_chan_int = (chan_int *)runtime_makechan(&RTYPE_chan_int);
  p_sync_WaitGroup = (sync_WaitGroup *)runtime_newobject(&RTYPE_sync_WaitGroup);
  v17 = p_sync_WaitGroup;
  v2 = 0;
  while ( a2 > v2 )
  {
    v13 = v2;
    v12 = *(_QWORD *)(a1 + 8 * v2);
    sync__ptr_WaitGroup_Add(p_sync_WaitGroup, 1);
    r0 = ($FA4B3C9BFF72A34B8428B600136518FC *)runtime_newobject(&RTYPE__FA4B3C9BFF72A34B8428B600136518FC);
    r0->F = (uintptr)main_idiomConcurrency_func1;
    if ( dword_610560 != 0 )
    {
      v21 = runtime_gcWriteBarrier2(r0, v4);
      r0 = ($FA4B3C9BFF72A34B8428B600136518FC *)v21._r0;
      v5 = v17;
      *(_QWORD *)v21._r8 = v17;
      v6 = p_chan_int;
      *(_QWORD *)(v21._r8 + 8LL) = p_chan_int;
    }
    else
    {
      v5 = v17;
      v6 = p_chan_int;
    }
    v16 = r0;
    r0->X0 = v5;
    r0->X1 = v6;
    p_struct__F_uintptr_X0_funcint_X1_int_ = (struct__F_uintptr_X0_funcint_X1_int_ *)runtime_newobject(&RTYPE_struct__F_uintptr_X0_funcint_X1_int_);
    p_struct__F_uintptr_X0_funcint_X1_int_->F = (uintptr)main_idiomConcurrency_gowrap1;
    if ( dword_610560 != 0 )
    {
      v22 = runtime_gcWriteBarrier1();
      p_struct__F_uintptr_X0_funcint_X1_int_ = (struct__F_uintptr_X0_funcint_X1_int_ *)v22._r0;
      v8 = (void (__golang **)(signed __int64))v16;
      *(_QWORD *)v22._r8 = v16;
    }
    else
    {
      v8 = (void (__golang **)(signed __int64))v16;
    }
    p_struct__F_uintptr_X0_funcint_X1_int_->X0 = v8;
    p_struct__F_uintptr_X0_funcint_X1_int_->X1 = v12;
    runtime_newproc();
    v2 = v13 + 1;
    p_sync_WaitGroup = v17;
  }
  sync__ptr_WaitGroup_Wait(p_sync_WaitGroup);
  runtime_closechan(p_chan_int);
  v9 = 0;
  while ( 1 )
  {
    v11 = v9;
    if ( (unsigned __int8)runtime_chanrecv2(p_chan_int, &v14) == 0 )
      break;
    v9 = v14 + v11;
    v14 = 0;
  }
  return v11;
}


// === main.idiomConcurrency.gowrap1 @ 0x4c3a60 ===
// main.idiomConcurrency.gowrap1
__int64 __golang main_idiomConcurrency_gowrap1()
{
  __int64 v0; // rdx

  return (**(__int64 (__golang ***)(_QWORD))(v0 + 8))(*(_QWORD *)(v0 + 16));
}


// === main.idiomConcurrency.func1 @ 0x4c3aa0 ===
// main.idiomConcurrency.func1
__int64 __golang main_idiomConcurrency_func1(__int64 a1)
{
  __int64 v1; // rdx
  __int64 v2; // rcx
  __int64 v3; // rdx
  __int64 v4; // rax
  __int64 v6; // [rsp+2h] [rbp-28h] BYREF
  _QWORD v7[2]; // [rsp+Ah] [rbp-20h] BYREF
  __int64 (__golang **v8)(__int64); // [rsp+1Ah] [rbp-10h]

  v8 = nullptr;
  v2 = *(_QWORD *)(v1 + 8);
  v3 = *(_QWORD *)(v1 + 16);
  v7[0] = main_idiomConcurrency_func1_deferwrap1;
  v7[1] = v2;
  v8 = (__int64 (__golang **)(__int64))v7;
  v6 = 3 * a1;
  v4 = runtime_chansend1(v3, &v6);
  return (*v8)(v4);
}


// === main.idiomConcurrency.func1.deferwrap1 @ 0x4c3b40 ===
// main.idiomConcurrency.func1.deferwrap1
void main_idiomConcurrency_func1_deferwrap1()
{
  __int64 v0; // rdx

  sync__ptr_WaitGroup_Add(*(_ptr_sync_WaitGroup *)(v0 + 8), -1);
}


// === main.idiomCryptoEncoding @ 0x4c3b80 ===
// main.idiomCryptoEncoding
retval_4C3B80 main_idiomCryptoEncoding()
{
  int v0; // edi
  int v1; // esi
  int v2; // r8d
  int v3; // r9d
  int v4; // r10d
  int v5; // r11d
  uint8 *v6; // rax
  __int64 v7; // rax
  __int64 v8; // rbx
  unsigned __int64 len; // rcx
  unsigned __int64 off; // r8
  __int64 v11; // rax
  __int64 v12; // rbx
  uint8 *v13; // rdx
  __int64 v14; // rcx
  unsigned __int64 v15; // rsi
  uint8 v21; // r8
  char v22; // r8
  __int64 r0; // rax
  __m256i v24; // [rsp+0h] [rbp-100h]
  __m256i v25; // [rsp+38h] [rbp-C8h] BYREF
  char v26[32]; // [rsp+58h] [rbp-A8h] BYREF
  char v27[8]; // [rsp+78h] [rbp-88h] BYREF
  __int64 v28; // [rsp+98h] [rbp-68h]
  __int64 v29; // [rsp+A0h] [rbp-60h]
  _BYTE v30[32]; // [rsp+A8h] [rbp-58h] BYREF
  __int64 v31; // [rsp+C8h] [rbp-38h] BYREF
  _ptr_crypto_rc4_Cipher v32; // [rsp+D0h] [rbp-30h]
  __int64 v33; // [rsp+D8h] [rbp-28h]
  uint8 *v34; // [rsp+E0h] [rbp-20h]
  _16_uint8 *p__16_uint8; // [rsp+E8h] [rbp-18h]
  bytes_Buffer *p_bytes_Buffer; // [rsp+F0h] [rbp-10h]
  retval_4A5480 v37; // 0:^0.16
  retval_4098C0 v38; // 0:kr00_16.16
  retval_4A42E0 v39; // 0:kr10_16.16
  retval_465780 v40; // 0:kr80_16.16
  retval_48F560 v41; // 0:kr90_16.16
  _slice_uint8 v42; // 0:rsi.24
  retval_465940 v43; // 0:kr20_24.24
  retval_4A5EC0 v44; // 0:kr48_24.24
  retval_4A4920 v45; // 0:kr60_32.32
  _slice_uint8 v46; // 0:rbx.8,8:rcx.8,16:rdi.8
  retval_4C3B80 result; // 0:rax.8,8:rbx.8,16:rcx.8,24:rdi.16

  v41 = strconv_Atoi();
  r0 = v41._r0;
  if ( v41._r1 != 0 )
    r0 = 1337;
  v38 = internal_strconv_FormatInt(r0, 10);
  v43 = runtime_stringtoslicebyte(v27, v38._r0, v38._r1);
  crypto_sha256_Sum256(v43._r0, v43._r1, v43._r2, v0, v1, v2, v3, v4, v5);
  v25 = v24;
  p__16_uint8 = (_16_uint8 *)runtime_newobject(&RTYPE__16_uint8);
  v37 = crypto_md5_Sum(&v25, 32, 32);
  v6 = (uint8 *)p__16_uint8;
  *(retval_4A5480 *)p__16_uint8 = v37;
  v44 = crypto_rc4_NewCipher(v6, 16, 16);
  if ( v44._r1 != 0 )
  {
    result._r0 = 0;
    result._r3 = v44._r1;
    result._r4 = v44._r2;
    result._r1 = 0;
    result._r2 = 0;
  }
  else
  {
    v32 = (_ptr_crypto_rc4_Cipher)v44._r0;
    v34 = (uint8 *)runtime_makeslice(&RTYPE_uint8, 32, 32);
    v46.array = v34;
    v46.len = 32;
    v46.cap = 32;
    v42.array = (uint8 *)&v25;
    v42.len = 32;
    v42.cap = 32;
    crypto_rc4__ptr_Cipher_XORKeyStream(v32, v46, v42);
    v45 = crypto_aes_NewCipher(&v25, 16, 32);
    if ( v45._r2 != 0 )
    {
      result._r0 = 0;
      result._r1 = 0;
      result._r4 = v45._r3;
      result._r3 = v45._r2;
      result._r2 = 0;
    }
    else
    {
      v39 = crypto_cipher_NewCBCEncrypter(v45._r0, v45._r1, (uint8 *)p__16_uint8, 16, 16);
      (*(void (__golang **)(_QWORD, uint8 *, __int64, __int64, uint8 *, __int64, __int64))(v39._r0 + 32LL))(
        v39._r1,
        v34,
        32,
        32,
        v34,
        32,
        32);
      v29 = *(_QWORD *)v34;
      p_bytes_Buffer = (bytes_Buffer *)runtime_newobject(&RTYPE_bytes_Buffer);
      v31 = v29;
      v7 = encoding_binary_Write(
             go_itab__ptr_bytes_Buffer_comma__ptr_io_Writer,
             p_bytes_Buffer,
             go_itab__ptr_binary_bigEndian_comma__ptr_binary_ByteOrder,
             &unk_610260,
             &RTYPE_uint64,
             &v31);
      len = p_bytes_Buffer->buf.len;
      off = p_bytes_Buffer->off;
      if ( len < off )
        runtime_panicBounds(v7, v8, len);
      v11 = encoding_base64__ptr_Encoding_EncodeToString(
              qword_5EFB60,
              &p_bytes_Buffer->buf.array[((__int64)(off - p_bytes_Buffer->buf.cap) >> 63) & off],
              len - off);
      memset(v30, 0, sizeof(v30));
      v13 = v34;
      v14 = 0;
      v15 = 0;
      while ( v14 < 8 )
      {
        v21 = v13[v14];
        if ( v15 >= 0x10 )
          runtime_panicBounds(v11, v12, v14);
        v30[v15] = a0123456789abcd[v21 >> 4];
        v22 = a0123456789abcd[v21 & 0xF];
        if ( v15 + 1 >= 0x10 )
          runtime_panicBounds(v11, v12, v14);
        v30[v15 + 1] = v22;
        ++v14;
        v15 += 2LL;
      }
      v28 = v12;
      v33 = v11;
      v40 = runtime_slicebytetostring(v26, v30, 16);
      result._r0 = runtime_concatbyte3(0, v33, v28, &unk_50CE48, 1, v40._r0, v40._r1);
      result._r3 = 0;
      result._r4 = 0;
    }
  }
  return result;
}


// === main.main @ 0x4c3ec0 ===
// main.main
void main_main()
{
  __int64 v0; // rdx
  const char *v1; // rcx
  unsigned __int64 v2; // rbx
  __int64 v3; // rax
  __int64 v4; // rax
  void *r0; // rax
  unsigned __int64 r1; // rbx
  __int64 r2; // rcx
  __int64 v8; // [rsp+0h] [rbp-80h]
  unsigned __int64 v9; // [rsp+8h] [rbp-78h]
  _QWORD v10[3]; // [rsp+10h] [rbp-70h] BYREF
  _QWORD v11[2]; // [rsp+28h] [rbp-58h] BYREF
  const char *v12; // [rsp+38h] [rbp-48h]
  __int64 v13; // [rsp+40h] [rbp-40h]
  __int128 v14; // [rsp+48h] [rbp-38h] BYREF
  _QWORD v15[5]; // [rsp+58h] [rbp-28h] BYREF
  retval_465780 v16; // 0:kr90_16.16
  retval_4C2F60 v17; // 0:kr20_40.40
  retval_4C3B80 v18; // 0:kr60_40.40

  if ( qword_5EFEB8 <= 1 )
  {
    v0 = 5;
    v1 = "12345";
  }
  else
  {
    v0 = *(_QWORD *)(qword_5EFEB0 + 24);
    v1 = *(const char **)(qword_5EFEB0 + 16);
  }
  v12 = v1;
  v8 = v0;
  v13 = main_idiomStringSlice((__int64)v1, v0);
  v9 = v2;
  v17 = main_idiomFileCLI(qword_5EFEB0, qword_5EFEB8);
  r0 = (void *)v17._r0;
  r1 = v17._r1;
  r2 = v17._r2;
  if ( v17._r1 == 0 )
  {
    r0 = &unk_610260;
    if ( v13 != 0 )
      r0 = (void *)v13;
    r1 = v9;
    r2 = v9;
  }
  v15[1] = v8;
  v15[0] = v12;
  v15[3] = 8;
  v15[2] = "flag_key";
  v11[0] = LOBYTE(main_idiomControlFlow((__int64)r0, r1, r2, 2)._r0);
  v11[1] = 99;
  v10[0] = main_idiomDataStructures(v15, 2, 2, (__int64)v11, 2);
  v10[1] = 10;
  v10[2] = 20;
  v3 = main_idiomConcurrency((__int64)v10, 3);
  internal_strconv_FormatInt(v3, 10);
  v18 = main_idiomCryptoEncoding();
  v14 = 0;
  v16 = runtime_slicebytetostring(0, v18._r0, v18._r1);
  v4 = runtime_convTstring(v16._r0, v16._r1);
  *(_QWORD *)&v14 = &RTYPE_string;
  *((_QWORD *)&v14 + 1) = v4;
  fmt_Fprintln(go_itab__ptr_os_File_comma__ptr_io_Writer, qword_5EFB88, &v14, 1, 1);
}


