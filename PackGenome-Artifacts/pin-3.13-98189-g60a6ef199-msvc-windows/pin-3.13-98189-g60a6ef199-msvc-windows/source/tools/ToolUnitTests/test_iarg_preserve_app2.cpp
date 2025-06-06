/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <stdio.h>
#if defined(TARGET_WINDOWS)
#include "windows.h"
#define EXPORT_CSYM extern "C" __declspec( dllexport )
#else
#define EXPORT_CSYM extern "C" 
#endif

#if defined(__cplusplus)
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif

EXTERN_C double var1;
double var1=2.0;
EXTERN_C double var2;
double var2=2.0;
EXTERN_C double var3;
double var3=2.0;
EXTERN_C double var4;
double var4=2.0;
EXTERN_C double var5;
double var5=2.0;

EXTERN_C void Fld1Fstp_a ();
EXTERN_C void Fld1Fstp_b ();
EXTERN_C void Fld1Fstp_c ();
EXTERN_C void Fld1Fstp_d ();
EXTERN_C void Fld1Fstp_e ();
EXTERN_C void Fld1Fstp_f ();
EXTERN_C void Fld1Fstp_g ();
EXTERN_C void Fld1Fstp_h ();
EXTERN_C void Fld1Fstp_i ();
EXTERN_C void Fld1Fstp_j ();
EXTERN_C void Fld1Fstp_k ();
EXTERN_C void Fld1Fstp_l ();
EXTERN_C void Fld1FstpSetXmmsMaskMxcsr ();

EXTERN_C void IntScratchFld1Fstp_a();
EXTERN_C void IntScratchFld1Fstp_b();
EXTERN_C void IntScratchFld1Fstp_c();
EXTERN_C void IntScratchFld1Fstp_d();

EXTERN_C void MaskZeroDivideInMxcsr();
EXTERN_C void UnMaskZeroDivideInMxcsr();

#if defined( __GNUC__)

#include <stdint.h>
typedef uint8_t  UINT8;   //LINUX HOSTS
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int8_t  INT8;
typedef int16_t INT16;
typedef int32_t INT32;
typedef int64_t INT64;

#define ALIGN16 __attribute__ ((aligned(16)))
#define ALIGN8  __attribute__ ((aligned(8)))

#elif defined(_MSC_VER)

typedef unsigned __int8 UINT8 ;
typedef unsigned __int16 UINT16;
typedef unsigned __int32 UINT32;
typedef unsigned __int64 UINT64;


#define ALIGN16 __declspec(align(16))
#define ALIGN8  __declspec(align(8))

#else
#error Expect usage of either GNU or MS compiler.
#endif

EXTERN_C UINT64 GetMxcsr();

#define MAX_BYTES_PER_XMM_REG 16
#define MAX_WORDS_PER_XMM_REG (MAX_BYTES_PER_XMM_REG/2)
#define MAX_DWORDS_PER_XMM_REG (MAX_WORDS_PER_XMM_REG/2)
#define MAX_QWORDS_PER_XMM_REG (MAX_DWORDS_PER_XMM_REG/2)
#define MAX_FLOATS_PER_XMM_REG (MAX_BYTES_PER_XMM_REG/sizeof(float))
#define MAX_DOUBLES_PER_XMM_REG (MAX_BYTES_PER_XMM_REG/sizeof(double))

union ALIGN16 xmm_reg_t
{
    UINT8  byte[MAX_BYTES_PER_XMM_REG];
    UINT16 word[MAX_WORDS_PER_XMM_REG];
    UINT32 dword[MAX_DWORDS_PER_XMM_REG];
    UINT64 qword[MAX_QWORDS_PER_XMM_REG];

    INT8   s_byte[MAX_BYTES_PER_XMM_REG];
    INT16  s_word[MAX_WORDS_PER_XMM_REG];
    INT32  s_dword[MAX_DWORDS_PER_XMM_REG];
    INT64  s_qword[MAX_QWORDS_PER_XMM_REG];

    float  flt[MAX_FLOATS_PER_XMM_REG];
    double dbl[MAX_DOUBLES_PER_XMM_REG];

};



#ifdef TARGET_IA32E
#define NUM_XMM_REGS 16
#if defined( __GNUC__)
#define NUM_XMM_SCRATCH_REGS 16
#else
#define NUM_XMM_SCRATCH_REGS 5
#endif
typedef UINT64 reg_t;
#else
#define NUM_XMM_REGS 8
#define NUM_XMM_SCRATCH_REGS 8
typedef UINT32 reg_t;
#endif


extern "C" reg_t get_gax();
extern "C" reg_t get_gcx();
extern "C" reg_t get_gdx();
#if defined(__GNUC__)
#include <stdint.h>
static void get_xmm_regA(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm0,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg0(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm0" :  : "m" (xmm_reg) : "%xmm0"  );
} 

static void get_xmm_reg0(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm0,%0" : "=m" (xmm_reg)  );
}


static void set_xmm_reg1(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm1" :  : "m" (xmm_reg) : "%xmm1"  );
} 

static void get_xmm_reg1(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm1, %0" : "=m" (xmm_reg)  );
}



static void set_xmm_reg2(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm2" :  : "m" (xmm_reg) : "%xmm2"  );
} 

static void get_xmm_reg2(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm2,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg3(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm3" :  : "m" (xmm_reg) : "%xmm3"  );
} 

static void get_xmm_reg3(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm3,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg4(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm4" :  : "m" (xmm_reg) : "%xmm4"  );
} 

static void get_xmm_reg4(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm4,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg5(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm5" :  : "m" (xmm_reg) : "%xmm5"  );
} 

static void get_xmm_reg5(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm5,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg6(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm6" :  : "m" (xmm_reg) : "%xmm6"  );
} 

static void get_xmm_reg6(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm6,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg7(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm7" :  : "m" (xmm_reg) : "%xmm7"  );
} 

static void get_xmm_reg7(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm7,%0" : "=m" (xmm_reg)  );
}
#ifdef TARGET_IA32E
static void get_xmm_reg8(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm8,%0" : "=m" (xmm_reg)  );
}


static void get_xmm_reg9(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm9,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg10(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm10,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg11(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm11,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg12(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm12,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg13(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm13,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg14(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm14,%0" : "=m" (xmm_reg)  );
}

static void get_xmm_reg15(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %%xmm15,%0" : "=m" (xmm_reg)  );
}

static void set_xmm_reg8(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm8" :  : "m" (xmm_reg) : "%xmm8"  );
}

static void set_xmm_reg9(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm9" :  : "m" (xmm_reg) : "%xmm9"  );
}

static void set_xmm_reg10(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm10" :  : "m" (xmm_reg) : "%xmm10"  );
}

static void set_xmm_reg11(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm11" :  : "m" (xmm_reg) : "%xmm11"  );
}

static void set_xmm_reg12(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm12" :  : "m" (xmm_reg) : "%xmm12"  );
}

static void set_xmm_reg13(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm13" :  : "m" (xmm_reg) : "%xmm13"  );
}

static void set_xmm_reg14(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm14" :  : "m" (xmm_reg) : "%xmm14"  );
}

static void set_xmm_reg15(xmm_reg_t& xmm_reg)
{
    asm volatile("movdqu %0, %%xmm15" :  : "m" (xmm_reg) : "%xmm15"  );
}

extern "C" reg_t get_r12();
extern "C" reg_t get_r13();
extern "C" reg_t get_r14();
extern "C" reg_t get_r15();
#endif

#else
extern "C" void set_xmm_reg0(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg0(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg1(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg1(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg2(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg2(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg3(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg3(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg4(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg4(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg5(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg5(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg6(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg6(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg7(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg7(xmm_reg_t& xmm_reg);
#ifdef TARGET_IA32E
extern "C" void set_xmm_reg8(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg8(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg9(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg9(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg10(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg10(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg11(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg11(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg12(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg12(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg13(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg13(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg14(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg14(xmm_reg_t& xmm_reg);
extern "C" void set_xmm_reg15(xmm_reg_t& xmm_reg);
extern "C" void get_xmm_reg15(xmm_reg_t& xmm_reg);

#endif
#endif
#ifdef TARGET_IA32E
extern "C" reg_t get_gdi();
extern "C" reg_t get_gdi();
extern "C" reg_t get_r8();
extern "C" reg_t get_r9();
extern "C" reg_t get_r10();
extern "C" reg_t get_r11();
#endif





static void
set_xmm_reg(xmm_reg_t& xmm_reg, UINT32 reg_no)
{

    switch (reg_no)
    {
    case 0:
        set_xmm_reg0(xmm_reg);
        break;
    case 1:
        set_xmm_reg1(xmm_reg);
        break;
    case 2:
        set_xmm_reg2(xmm_reg);
        break;
    case 3:
        set_xmm_reg3(xmm_reg);
        break;
    case 4:
        set_xmm_reg4(xmm_reg);
        break;
    case 5:
        set_xmm_reg5(xmm_reg);
        break;
    case 6:
        set_xmm_reg6(xmm_reg);
        break;
    case 7:
        set_xmm_reg7(xmm_reg);
        break;
#ifdef TARGET_IA32E
    case 8:
        set_xmm_reg8(xmm_reg);
        break;
    case 9:
        set_xmm_reg9(xmm_reg);
        break;
    case 10:
        set_xmm_reg10(xmm_reg);
        break;
    case 11:
        set_xmm_reg11(xmm_reg);
        break;
    case 12:
        set_xmm_reg12(xmm_reg);
        break;
    case 13:
        set_xmm_reg13(xmm_reg);
        break;
    case 14:
        set_xmm_reg14(xmm_reg);
        break;
    case 15:
        set_xmm_reg15(xmm_reg);
        break;
#endif
    }

} 
static void
get_xmm_reg(xmm_reg_t& xmm_reg, UINT32 reg_no)
{
    switch (reg_no)
    {
    case 0:
       get_xmm_reg0(xmm_reg);
       break;
    case 1:
        get_xmm_reg1(xmm_reg);
        break;
    case 2:
        get_xmm_reg2(xmm_reg);
        break;
    case 3:
        get_xmm_reg3(xmm_reg);
        break;
    case 4:
        get_xmm_reg4(xmm_reg);
        break;
    case 5:
        get_xmm_reg5(xmm_reg);
        break;
    case 6:
        get_xmm_reg6(xmm_reg);
        break;
    case 7:
        get_xmm_reg7(xmm_reg);
        break;
#ifdef TARGET_IA32E
    case 8:
        get_xmm_reg8(xmm_reg);
        break;
    case 9:
        get_xmm_reg9(xmm_reg);
        break;
    case 10:
        get_xmm_reg10(xmm_reg);
        break;
    case 11:
        get_xmm_reg11(xmm_reg);
        break;
    case 12:
        get_xmm_reg12(xmm_reg);
        break;
    case 13:
        get_xmm_reg13(xmm_reg);
        break;
    case 14:
        get_xmm_reg14(xmm_reg);
        break;
    case 15:
        get_xmm_reg15(xmm_reg);
        break;
#endif
    }

}
void write_xmm_reg(UINT32 reg_no, UINT32 val)
{

    xmm_reg_t xmm;
    xmm.dword[0] = val;
    xmm.dword[1] = val;
    xmm.dword[2] = val;
    xmm.dword[3] = val;
    
    set_xmm_reg(xmm, reg_no); 
}

void read_xmm_reg(UINT32 reg_no, xmm_reg_t& xmm)
{

    xmm.dword[0] = 0;
    xmm.dword[1] = 0;
    xmm.dword[2] = 0;
    xmm.dword[3] = 0;
    
    get_xmm_reg(xmm, reg_no); 
}

EXPORT_CSYM void TestIargPreserveInReplacement()
{
}

EXPORT_CSYM void TestIargPreserveInReplacement1()
{
}

EXPORT_CSYM void TestIargPreserveInReplacement2()
{
}

EXPORT_CSYM void  TestIargPreserveInProbed()
{
}

EXPORT_CSYM void  TestIargPreserveInProbed1()
{
}

EXPORT_CSYM void  TestIargPreserveInProbed2()
{
}

extern "C" ALIGN16 UINT64 vals[];
ALIGN16 UINT64 vals[]={1,0,2,0,3,0,4,0,5,0,6,0,7,0,8,0,9,0,10,0,11,0,12,0,13,0,14,0,15,0,16,0};

extern "C"  UINT64* val1;
extern "C"  UINT64* val2;
extern "C"  UINT64* val3;
extern "C"  UINT64* val4;
extern "C"  UINT64* val5;
extern "C"  UINT64* val6;
extern "C"  UINT64* val7;
extern "C"  UINT64* val8;
extern "C"  UINT64* val9;
extern "C"  UINT64* val10;
extern "C"  UINT64* val11;
extern "C"  UINT64* val12;
extern "C"  UINT64* val13;
extern "C"  UINT64* val14;
extern "C"  UINT64* val15;
extern "C"  UINT64* val16;
UINT64* val1=&vals[0];
UINT64* val2=&vals[2];
UINT64* val3=&vals[4];
UINT64* val4=&vals[6];
UINT64* val5=&vals[8];
UINT64* val6=&vals[10];
UINT64* val7=&vals[12];
UINT64* val8=&vals[14];
UINT64* val9=&vals[16];
UINT64* val10=&vals[18];
UINT64* val11=&vals[20];
UINT64* val12=&vals[22];
UINT64* val13=&vals[24];
UINT64* val14=&vals[26];
UINT64* val15=&vals[28];
UINT64* val16=&vals[30];

#if defined(TARGET_IA32)
typedef UINT32 ADDRINT;
#else
typedef UINT64 ADDRINT;
#endif

extern "C" ADDRINT setFlagsX;
ADDRINT setFlagsX=0;

int main()
{

    var1=2.0;
    var2=2.0;
    var3=2.0;

    // the test_iarg_preserve tool will insert a call to an analysis routine  
    // after the third fld1 in Fld1Fstp that sets the first 3 x87 regs to 0
    Fld1Fstp_a();

    // make sure the values were changed by the tool test_iarg_preserve - since that tool
    // specified that it's analysis routine preserved the x87 regs when it doesn't
    if (var1 != 0.0 || var2 != 0.0 || var3 != 0.0)
    {
        printf ("***Error in x87 values_1\n");
        return (-1);
    }

    var1=2.0;
    var2=2.0;
    var3=2.0;

    // the test_iarg_preserve tool will insert a call to an analysis routine  
    // after the third fld1 in Fld1Fstp that sets the first 3 x87 regs to 0
    Fld1Fstp_b();

    
    // make sure the values were changed by the tool test_iarg_preserve - since this test
    // is run with -bridge_save_x87 0
    if (var1 != 0.0 || var2 != 0.0 || var3 != 0.0)
    {
        printf ("***Error in x87 values_2\n");
        return (-1);
    }
    
    var1=2.0;
    var2=2.0;
    var3=2.0;

    // the test_iarg_preserve tool will insert a call to an analysis routine  
    // after the third fld1 in Fld1Fstp that sets the first 3 x87 regs to 0
    Fld1Fstp_c();
    
    // make sure the values were changed by the tool test_iarg_preserve - since this test
    // is run with -bridge_save_x87 0
    if (var1 != 0.0 || var2 != 0.0 || var3 != 0.0)
    {
        printf ("***Error in x87 values_3\n");
        return (-1);
    }
    

    var1=2.0;
    var2=2.0;
    var3=2.0;

    // the test_iarg_preserve tool will insert a call to an analysis routine  
    // after the third fld1 in Fld1Fstp that sets the first 3 x87 regs to 0
    Fld1Fstp_d();

    
    // make sure the values were changed by the tool test_iarg_preserve - since this test
    // is run with -bridge_save_x87 0
    if (var1 != 0.0 || var2 != 0.0 || var3 != 0.0)
    {
        printf ("***Error in x87 values_4\n");
        return (-1);
    }

    
    return(0);
}

