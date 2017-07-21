/**
 * (c) 2014-2017 Capstone.JS
 * Wrapper made by Alexandro Sanchez Bach.
 */
import {CapstoneConstant} from './capstone-constants';

type EnvironmentType = "WEB" | "NODE" | "SHELL" | "WORKER";

declare class MCapstone {
    constructor();

    print(str: string): void;
    printErr(str: string): void;
    arguments: string[];
    environment: EnvironmentType;
    preInit: { ():  void }[];
    preRun: { ():  void }[];
    postRun: { ():  void }[];
    preinitializedWebGLContext: WebGLRenderingContext;
    noInitialRun: boolean;
    noExitRuntime: boolean;
    logReadFiles: boolean;
    filePackagePrefixURL: string;
    wasmBinary: ArrayBuffer;

    destroy(object: object): void;
    getPreloadedPackage(remotePackageName: string, remotePackageSize: number): ArrayBuffer;
    locateFile(url: string): string;
    onCustomMessage(event: MessageEvent): void;

    Runtime: any;

    ccall(ident: string, returnType: string, argTypes: string[], args: any[]): any;
    cwrap(ident: string, returnType: string, argTypes: string[]): any;

    setValue(ptr: number, value: any, type: string, noSafe?: boolean): void;
    getValue(ptr: number, type: string, noSafe?: boolean): number;

    Pointer_stringify(ptr: number, length?: number): string;
    writeArrayToMemory(array: number[], buffer: number): void;    

    _malloc(size: number): number;
    _free(ptr: number): void;
}

export namespace cs {
    // Emscripten demodularize
    let mCapstone = new MCapstone();

    const enum Error {
        // Return codes
        ERR_OK = 0,         // No error: everything was fine
        ERR_MEM = 1,        // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
        ERR_ARCH = 2,       // Unsupported architecture: cs_open()
        ERR_HANDLE = 3,     // Invalid handle: cs_op_count(), cs_op_index()
        ERR_CSH = 4,        // Invalid csh argument: cs_close(), cs_errno(), cs_option()
        ERR_MODE = 5,       // Invalid/unsupported mode: cs_open()
        ERR_OPTION = 6,     // Invalid/unsupported option: cs_option()
        ERR_DETAIL = 7,     // Information is unavailable because detail option is OFF
        ERR_MEMSETUP = 8,   // Dynamic memory management uninitialized (see OPT_MEM)
        ERR_VERSION = 9,    // Unsupported version (bindings)
        ERR_DIET = 10,      // Access irrelevant data in "diet" engine
        ERR_SKIPDATA = 11,  // Access irrelevant data for "data" instruction in SKIPDATA mode
        ERR_X86_ATT = 12,   // X86 AT&T syntax is unsupported (opt-out at compile time)
        ERR_X86_INTEL = 13 // X86 Intel syntax is unsupported (opt-out at compile time)
    }

    const enum Arch {
        // Architectures
        ARCH_ARM = 0,       // ARM architecture (including Thumb, Thumb-2)
        ARCH_ARM64 = 1,     // ARM-64, also called AArch64
        ARCH_MIPS = 2,      // Mips architecture
        ARCH_X86 = 3,       // X86 architecture (including x86 & x86-64)
        ARCH_PPC = 4,       // PowerPC architecture
        ARCH_SPARC = 5,     // Sparc architecture
        ARCH_SYSZ = 6,      // SystemZ architecture
        ARCH_XCORE = 7,     // XCore architecture
        ARCH_MAX = 8,
        ARCH_ALL = 0xFFFF
    }

    const enum Mode {
        // Modes
        MODE_LITTLE_ENDIAN = 0,     // Little-Endian mode (default mode)
        MODE_ARM = 0,               // 32-bit ARM
        MODE_16 = 1 << 1,           // 16-bit mode (X86)
        MODE_32 = 1 << 2,           // 32-bit mode (X86)
        MODE_64 = 1 << 3,           // 64-bit mode (X86, PPC)
        MODE_THUMB = 1 << 4,        // ARM's Thumb mode, including Thumb-2
        MODE_MCLASS = 1 << 5,       // ARM's Cortex-M series
        MODE_V8 = 1 << 6,           // ARMv8 A32 encodings for ARM
        MODE_MICRO = 1 << 4,        // MicroMips mode (MIPS)
        MODE_MIPS3 = 1 << 5,        // Mips III ISA
        MODE_MIPS32R6 = 1 << 6,     // Mips32r6 ISA
        MODE_MIPSGP64 = 1 << 7,     // General Purpose Registers are 64-bit wide (MIPS)
        MODE_V9 = 1 << 4,           // SparcV9 mode (Sparc)
        MODE_BIG_ENDIAN = 1 << 31,  // Big-Endian mode
        MODE_MIPS32 = 1 << 2,       // Mips32 ISA (Mips)
        MODE_MIPS64 = 1 << 3        // Mips64 ISA (Mips)
    }

    const enum Option {
        // Options
        OPT_SYNTAX = 1,             // Intel X86 asm syntax (CS_ARCH_X86 arch)
        OPT_DETAIL = 2,             // Break down instruction structure into details
        OPT_MODE = 3,               // Change engine's mode at run-time
        OPT_MEM = 4,                // Change engine's mode at run-time
        OPT_SKIPDATA = 5,           // Skip data when disassembling
        OPT_SKIPDATA_SETUP = 6      // Setup user-defined function for SKIPDATA option
    }

    const enum OptionValue {
        // Capstone option value
        OPT_OFF = 0,                // Turn OFF an option - default option of CS_OPT_DETAIL
        OPT_ON = 3                  // Turn ON an option (CS_OPT_DETAIL)
    }

    const enum Syntax {
        // Capstone syntax value
        OPT_SYNTAX_DEFAULT = 0,     // Default assembly syntax of all platforms (CS_OPT_SYNTAX)
        OPT_SYNTAX_INTEL = 1,       // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
        OPT_SYNTAX_ATT = 2,         // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
        OPT_SYNTAX_NOREGNAME = 3,   // Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)  
    }

    const enum InstructionGroup {
        // Common instruction groups - to be consistent across all architectures.
        GRP_INVALID = 0,            // uninitialized/invalid group.
        GRP_JUMP = 1,               // all jump instructions (conditional+direct+indirect jumps)
        GRP_CALL = 2,               // all call instructions
        GRP_RET = 3,                // all return instructions
        GRP_INT = 4,                // all interrupt instructions (int+syscall)
        GRP_IRET = 5                // all interrupt return instructions
    }

    const enum InstructionType {
        // Common instruction operand types - to be consistent across all architectures.
        OP_INVALID = 0,
        OP_REG = 1,
        OP_IMM = 2,
        OP_MEM = 3,
        OP_FP = 4
    }

    const enum Support {
        // query id for cs_support()
        SUPPORT_DIET = 0xFFFF + 1,
        SUPPORT_X86_REDUCE = 0xFFFF + 2,
    }

    export const version = function() {
        const major_ptr = mCapstone._malloc(4);
        const minor_ptr = mCapstone._malloc(4);
        let ret = mCapstone.ccall('cs_version', 'number',
            ['pointer', 'pointer'], [major_ptr, minor_ptr]);
        const major = mCapstone.getValue(major_ptr, 'i32');
        const minor = mCapstone.getValue(minor_ptr, 'i32');
        mCapstone._free(major_ptr);
        mCapstone._free(minor_ptr);
        return ret;
    };

    export const support = function(query) {
        let ret = mCapstone.ccall('cs_support', 'number', ['number'], [query]);
        return ret;
    };

    export const strerror = function(code) {
        let ret = mCapstone.ccall('cs_strerror', 'string', ['number'], [code]);
        return ret;
    };

    /**
     * Instruction object
     */
    export const Instruction = function (pointer, arch) {
        // Instruction ID
        this.id = mCapstone.getValue(pointer, 'i32');

        // Address (EIP) of this instruction
        this.address = mCapstone.getValue(pointer + 8, 'i64');

        // Size of this instruction
        this.size = mCapstone.getValue(pointer + 16, 'i16');

        // Machine bytes of this instruction (length indicated by @size above)
        this.bytes = [];
        for (let i = 0; i < this.size; i++) {
            let byteValue = mCapstone.getValue(pointer + 18 + i, 'i8');
            if (byteValue < 0) {
                byteValue = 256 + byteValue;
            }
            this.bytes.push(byteValue);
        }

        // ASCII representation of instruction mnemonic
        this.mnemonic = mCapstone.Pointer_stringify(pointer + 34);

        // ASCII representation of instruction operands
        this.op_str = mCapstone.Pointer_stringify(pointer + 66);

        // Details
        let detail = {
            regs_read: [],
            regs_write: [],
            groups: [],
            usermode: false,
            vector_size: 0,
            vector_data: 0,
            cps_mode: 0,
            cps_flag: 0,
            cc: 0,
            update_flags: false,
            writeback: false,
            mem_barrier: 0,
            shift: undefined,
            type: 0,
            op: [],
            prefix: [],
            opcode: [],
            rex: 0,
            addr_size: 0,
            modrm: 0,
            sib: 0,
            disp: 0,
            sib_index: 0,
            sib_scale: 0,
            sib_base: 0,
            sse_cc: 0,
            avx_cc: 0,
            avx_sae: 0,
            avx_rm: 0,
            bc: 0,
            bh: 0,
            update_cr0: 0,
            hint: 0
        };
        let detail_addr = mCapstone.getValue(pointer + 228, '*');
        if (detail_addr != 0) {
            // Architecture-agnostic instruction info
            detail.regs_read = [];
            let regs_read_count = mCapstone.getValue(detail_addr + 12, 'i8');
            for (let i = 0; i < regs_read_count; i++) {
                detail.regs_read[i] = mCapstone.getValue(detail_addr + 0 + i, 'i8');
            }
            detail.regs_write = [];
            let regs_write_count = mCapstone.getValue(detail_addr + 33, 'i8');
            for (let i = 0; i < regs_write_count; i++) {
                detail.regs_write[i] = mCapstone.getValue(detail_addr + 13 + i, 'i8');
            }
            detail.groups = [];
            let groups_count = mCapstone.getValue(detail_addr + 42, 'i8');
            for (let i = 0; i < groups_count; i++) {
                detail.groups[i] = mCapstone.getValue(detail_addr + 34 + i, 'i8');
            }
            // Architecture-specific instruction info
            let arch_info_addr = detail_addr + 44;

            let op_size;
            let op_count;

            switch (arch) {
            case Arch.ARCH_ARM:
                detail.usermode = Boolean(mCapstone.getValue(arch_info_addr + 0x00, 'i8'));
                detail.vector_size = mCapstone.getValue(arch_info_addr + 0x04, 'i32');
                detail.vector_data = mCapstone.getValue(arch_info_addr + 0x08, 'i32');
                detail.cps_mode = mCapstone.getValue(arch_info_addr + 0x0C, 'i32');
                detail.cps_flag = mCapstone.getValue(arch_info_addr + 0x10, 'i32');
                detail.cc = mCapstone.getValue(arch_info_addr + 0x14, 'i32');
                detail.update_flags = Boolean(mCapstone.getValue(arch_info_addr + 0x18, 'i8'));
                detail.writeback = Boolean(mCapstone.getValue(arch_info_addr + 0x19, 'i8'));
                detail.mem_barrier = mCapstone.getValue(arch_info_addr + 0x1C, 'i32');
                // Operands
                op_size = 36;
                op_count = mCapstone.getValue(arch_info_addr + 0x20, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        vector_index: 0,
                        shift: {
                            type: 0,
                            value: 0
                        },
                        type: 0,
                        subtracted: false,
                        reg: 0,
                        imm: 0,
                        fp: 0,
                        setend: 0,
                        mem: {
                            base: 0,
                            index: 0,
                            scale: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x24 + (i * op_size);
                    op.vector_index = mCapstone.getValue(op_addr + 0, 'i32');
                    op.shift = {
                        type:  mCapstone.getValue(op_addr + 4, 'i32'),
                        value: mCapstone.getValue(op_addr + 8, 'i32'),
                    };
                    op.type = mCapstone.getValue(op_addr + 12, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.ARM_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 16, 'i32');
                        break;
                    case CapstoneConstant.ARM_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 16, 'i32');
                        break;
                    case CapstoneConstant.ARM_OP_FP:
                        op.fp = mCapstone.getValue(op_addr + 16, 'double');
                        break;
                    case CapstoneConstant.ARM_OP_SETEND:
                        op.setend = mCapstone.getValue(op_addr + 16, 'i32');
                        break;
                    case CapstoneConstant.ARM_OP_MEM:
                        op.mem = {
                            base:  mCapstone.getValue(op_addr + 16, 'i32'),
                            index: mCapstone.getValue(op_addr + 20, 'i32'),
                            scale: mCapstone.getValue(op_addr + 24, 'i32'),
                            disp:  mCapstone.getValue(op_addr + 28, 'i32'),
                        };
                        break;
                    }
                    op.subtracted = Boolean(mCapstone.getValue(arch_info_addr + 32, 'i8'));
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_ARM64:
                detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                detail.update_flags = Boolean(mCapstone.getValue(arch_info_addr + 0x04, 'i8'));
                detail.writeback = Boolean(mCapstone.getValue(arch_info_addr + 0x05, 'i8'));
                // Operands
                op_size = 40;
                op_count = mCapstone.getValue(arch_info_addr + 0x06, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        vector_index: 0,
                        vas: 0,
                        shift: {
                            type: 0,
                            value: 0
                        },
                        vess: 0,
                        ext: 0,
                        type: 0,
                        reg: 0,
                        imm: 0,
                        fp: 0,
                        pstate: 0,
                        sys: 0,
                        barrier: 0,
                        prefetch: 0,
                        mem: {
                            base: 0,
                            index: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x08 + (i * op_size);
                    op.vector_index = mCapstone.getValue(op_addr + 0, 'i32');
                    op.vas = mCapstone.getValue(op_addr + 4, 'i32');
                    op.vess = mCapstone.getValue(op_addr + 8, 'i32');
                    op.shift = {
                        type:  mCapstone.getValue(op_addr + 12, 'i32'),
                        value: mCapstone.getValue(op_addr + 16, 'i32'),
                    };
                    op.ext = mCapstone.getValue(op_addr + 20, 'i32');
                    op.type = mCapstone.getValue(op_addr + 24, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.ARM64_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 28, 'i32');
                        break;
                    case CapstoneConstant.ARM64_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 28, 'i64');
                        break;
                    case CapstoneConstant.ARM64_OP_FP:
                        op.fp = mCapstone.getValue(op_addr + 28, 'double');
                        break;
                    case CapstoneConstant.ARM64_OP_PSTATE:
                        op.pstate = mCapstone.getValue(op_addr + 28, 'i32');
                        break;
                    case CapstoneConstant.ARM64_OP_SYS:
                        op.sys = mCapstone.getValue(op_addr + 28, 'i32');
                        break;
                    case CapstoneConstant.ARM64_OP_BARRIER:
                        op.barrier = mCapstone.getValue(op_addr + 28, 'i32');
                        break;
                    case CapstoneConstant.ARM64_OP_PREFETCH:
                        op.prefetch = mCapstone.getValue(op_addr + 28, 'i32');
                        break;
                    case CapstoneConstant.ARM64_OP_MEM:
                        op.mem = {
                            base:  mCapstone.getValue(op_addr + 28, 'i32'),
                            index: mCapstone.getValue(op_addr + 32, 'i32'),
                            disp:  mCapstone.getValue(op_addr + 36, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_MIPS:
                // Operands
                op_size = 16;
                op_count = mCapstone.getValue(arch_info_addr + 0x00, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        mem: {
                            base: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x04 + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.MIPS_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.MIPS_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i64');
                        break;
                    case CapstoneConstant.MIPS_OP_MEM:
                        op.mem = {
                            base: mCapstone.getValue(op_addr + 4, 'i32'),
                            disp: mCapstone.getValue(op_addr + 8, 'i64'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_X86:
                detail.prefix = [];
                detail.prefix[0] = mCapstone.getValue(arch_info_addr + 0x00, 'i8');
                detail.prefix[1] = mCapstone.getValue(arch_info_addr + 0x01, 'i8');
                detail.prefix[2] = mCapstone.getValue(arch_info_addr + 0x02, 'i8');
                detail.prefix[3] = mCapstone.getValue(arch_info_addr + 0x03, 'i8');
                detail.opcode = [];
                detail.opcode[0] = mCapstone.getValue(arch_info_addr + 0x04, 'i8');
                detail.opcode[1] = mCapstone.getValue(arch_info_addr + 0x05, 'i8');
                detail.opcode[2] = mCapstone.getValue(arch_info_addr + 0x06, 'i8');
                detail.opcode[3] = mCapstone.getValue(arch_info_addr + 0x07, 'i8');
                detail.rex = mCapstone.getValue(arch_info_addr + 0x08, 'i8');
                detail.addr_size = mCapstone.getValue(arch_info_addr + 0x09, 'i8');
                detail.modrm = mCapstone.getValue(arch_info_addr + 0x0A, 'i8');
                detail.sib = mCapstone.getValue(arch_info_addr + 0x0B, 'i8');
                detail.disp = mCapstone.getValue(arch_info_addr + 0x0C, 'i32');
                detail.sib_index = mCapstone.getValue(arch_info_addr + 0x10, 'i32');
                detail.sib_scale = mCapstone.getValue(arch_info_addr + 0x14, 'i8');
                detail.sib_base = mCapstone.getValue(arch_info_addr + 0x18, 'i32');
                detail.sse_cc = mCapstone.getValue(arch_info_addr + 0x1C, 'i32');
                detail.avx_cc = mCapstone.getValue(arch_info_addr + 0x20, 'i32');
                detail.avx_sae = mCapstone.getValue(arch_info_addr + 0x24, 'i8');
                detail.avx_rm = mCapstone.getValue(arch_info_addr + 0x28, 'i32');
                // Operands
                op_size = 40;
                op_count = mCapstone.getValue(arch_info_addr + 0x2C, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        fp: 0,
                        mem: {
                            segment: 0,
                            base: 0,
                            index: 0,
                            scale: 0,
                            disp: 0
                        },
                        size: 0,
                        avx_bcast: 0,
                        avx_zero_opmask: 0
                    };
                    let op_addr = arch_info_addr + 0x30 + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.X86_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.X86_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i64');
                        break;
                    case CapstoneConstant.X86_OP_FP:
                        op.fp = mCapstone.getValue(op_addr + 4, 'double');
                        break;
                    case CapstoneConstant.X86_OP_MEM:
                        op.mem = {
                            segment:  mCapstone.getValue(op_addr +  4, 'i32'),
                            base:     mCapstone.getValue(op_addr +  8, 'i32'),
                            index:    mCapstone.getValue(op_addr + 12, 'i32'),
                            scale:    mCapstone.getValue(op_addr + 16, 'i32'),
                            disp:     mCapstone.getValue(op_addr + 20, 'i64'),
                        };
                        break;
                    }
                    op.size = mCapstone.getValue(op_addr + 28, 'i8');
                    op.avx_bcast = mCapstone.getValue(op_addr + 32, 'i32');
                    op.avx_zero_opmask = mCapstone.getValue(op_addr + 36, 'i8');
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_PPC:
                detail.bc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                detail.bh = mCapstone.getValue(arch_info_addr + 0x04, 'i32');
                detail.update_cr0 = mCapstone.getValue(arch_info_addr + 0x08, 'i8');
                // Operands
                op_size = 16;
                op_count = mCapstone.getValue(arch_info_addr + 0x09, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        crx: {
                            scale: 0,
                            reg: 0,
                            cond: 0
                        },
                        mem: {
                            base: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x0C + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.PPC_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.PPC_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.PPC_OP_CRX:
                        op.crx = {
                            scale:  mCapstone.getValue(op_addr +  4, 'i32'),
                            reg:    mCapstone.getValue(op_addr +  8, 'i32'),
                            cond:   mCapstone.getValue(op_addr + 12, 'i32'),
                        };
                        break;
                    case CapstoneConstant.PPC_OP_MEM:
                        op.mem = {
                            base:   mCapstone.getValue(op_addr +  4, 'i32'),
                            disp:   mCapstone.getValue(op_addr +  8, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_SPARC:
                detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                detail.hint = mCapstone.getValue(arch_info_addr + 0x04, 'i32');
                // Operands
                op_size = 12;
                op_count = mCapstone.getValue(arch_info_addr + 0x08, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        mem: {
                            base: 0,
                            index: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x09 + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.SPARC_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.SPARC_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.SPARC_OP_MEM:
                        op.mem = {
                            base:   mCapstone.getValue(op_addr + 4, 'i8'),
                            index:  mCapstone.getValue(op_addr + 5, 'i8'),
                            disp:   mCapstone.getValue(op_addr + 8, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_SYSZ:
                detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                // Operands
                op_size = 24;
                op_count = mCapstone.getValue(arch_info_addr + 0x04, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        mem: {
                            base: 0,
                            index: 0,
                            length: 0,
                            disp: 0
                        }
                    };
                    let op_addr = arch_info_addr + 0x08 + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.SYSZ_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.SYSZ_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.SYSZ_OP_MEM:
                        op.mem = {
                            base:   mCapstone.getValue(op_addr +  4, 'i8'),
                            index:  mCapstone.getValue(op_addr +  5, 'i8'),
                            length: mCapstone.getValue(op_addr +  8, 'i64'),
                            disp:   mCapstone.getValue(op_addr + 16, 'i64'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Arch.ARCH_XCORE:
                // Operands
                op_size = 16;
                op_count = mCapstone.getValue(arch_info_addr + 0, 'i8');
                for (let i = 0; i < op_count; i++) {
                    let op = {
                        type: 0,
                        reg: 0,
                        imm: 0,
                        mem: {
                            base: 0,
                            index: 0,
                            disp: 0,
                            direct: 0
                        }
                    };
                    let op_addr = arch_info_addr + 4 + (i * op_size);
                    op.type = mCapstone.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case CapstoneConstant.XCORE_OP_REG:
                        op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.XCORE_OP_IMM:
                        op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                        break;
                    case CapstoneConstant.XCORE_OP_MEM:
                        op.mem = {
                            base:   mCapstone.getValue(op_addr +  4, 'i8'),
                            index:  mCapstone.getValue(op_addr +  5, 'i8'),
                            disp:   mCapstone.getValue(op_addr +  8, 'i32'),
                            direct: mCapstone.getValue(op_addr + 12, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;
            }
        }
        this.detail = detail;
    };

    /**
     * Capstone object
     */
    export const Capstone = function (arch, mode) {
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = mCapstone._malloc(4);

        // Options
        this.option = function(option, value) {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            if (!handle) {
                return;
            }
            let ret = mCapstone.ccall('cs_option', 'number',
                ['pointer', 'number', 'number'],
                [handle, option, value]
            );
            if (ret != Error.ERR_OK) {
                let error = 'Capstone.js: Function cs_option failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
        }

        // Disassemble
        this.disasm = function (buffer, addr, max) {
            let handle = mCapstone.getValue(this.handle_ptr, 'i32');

            // Allocate buffer and copy data
            let buffer_len = buffer.length;
            let buffer_ptr = mCapstone._malloc(buffer_len);
            mCapstone.writeArrayToMemory(buffer, buffer_ptr);

            // Pointer to the instruction array
            let insn_ptr_ptr = mCapstone._malloc(4);

            let count = mCapstone.ccall('cs_disasm', 'number',
                ['number', 'pointer', 'number', 'number', 'number', 'pointer'],
                [handle, buffer_ptr, buffer_len, addr, 0, max || 0, insn_ptr_ptr]
            );
            if (count == 0 && buffer_len != 0) {
                mCapstone._free(insn_ptr_ptr);
                mCapstone._free(buffer_ptr);

                let code = this.errno();
                let error = 'Capstone.js: Function cs_disasm failed with code ' + code + ':\n' + cs.strerror(code);
                throw error;
            }

            // Dereference intruction array
            let insn_ptr = mCapstone.getValue(insn_ptr_ptr, 'i32');
            let insn_size = 232;
            let instructions = [];

            // Save instructions
            for (let i = 0; i < count; i++) {
                instructions.push(new cs.Instruction(insn_ptr + i * insn_size, this.arch));
            }

            count = mCapstone.ccall('cs_free', 'void',
                ['pointer', 'number'],
                [insn_ptr, count]
            );

            mCapstone._free(insn_ptr_ptr);
            mCapstone._free(buffer_ptr);
            return instructions;
        };

        this.reg_name = function(reg_id) {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            let ret = mCapstone.ccall('cs_reg_name', 'string', ['pointer', 'number'], [handle, reg_id]);
            return ret;
        }

        this.insn_name = function(insn_id) {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            let ret = mCapstone.ccall('cs_insn_name', 'string', ['pointer', 'number'], [handle, insn_id]);
            return ret;
        }

        this.group_name = function(group_id) {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            let ret = mCapstone.ccall('cs_group_name', 'string', ['pointer', 'number'], [handle, group_id]);
            return ret;
        }

        this.errno = function() {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            let ret = mCapstone.ccall('cs_errno', 'number', ['pointer'], [handle]);
            return ret;
        }

        this.close = function() {
            let handle = mCapstone.getValue(this.handle_ptr, '*');
            let ret = mCapstone.ccall('cs_close', 'number', ['pointer'], [handle]);
            if (ret != Error.ERR_OK) {
                let error = 'Capstone.js: Function cs_close failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
            mCapstone._free(this.handle_ptr);
        }


        // Constructor
        let ret = mCapstone.ccall('cs_open', 'number',
            ['number', 'number', 'pointer'],
            [this.arch, this.mode, this.handle_ptr]
        );

        if (ret != Error.ERR_OK) {
            mCapstone.setValue(this.handle_ptr, 0, '*');
            let error = 'Capstone.js: Function cs_open failed with code ' + ret + ':\n' + cs.strerror(ret);
            throw error;
        }
    };
}

