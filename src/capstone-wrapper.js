"use strict";
exports.__esModule = true;
var cs;
(function (cs) {
    // Emscripten demodularize
    var mCapstone = new MCapstone();
    cs.version = function () {
        var major_ptr = mCapstone._malloc(4);
        var minor_ptr = mCapstone._malloc(4);
        var ret = mCapstone.ccall('cs_version', 'number', ['pointer', 'pointer'], [major_ptr, minor_ptr]);
        var major = mCapstone.getValue(major_ptr, 'i32');
        var minor = mCapstone.getValue(minor_ptr, 'i32');
        mCapstone._free(major_ptr);
        mCapstone._free(minor_ptr);
        return ret;
    };
    cs.support = function (query) {
        var ret = mCapstone.ccall('cs_support', 'number', ['number'], [query]);
        return ret;
    };
    cs.strerror = function (code) {
        var ret = mCapstone.ccall('cs_strerror', 'string', ['number'], [code]);
        return ret;
    };
    /**
     * Instruction object
     */
    cs.Instruction = function (pointer, arch) {
        // Instruction ID
        this.id = mCapstone.getValue(pointer, 'i32');
        // Address (EIP) of this instruction
        this.address = mCapstone.getValue(pointer + 8, 'i64');
        // Size of this instruction
        this.size = mCapstone.getValue(pointer + 16, 'i16');
        // Machine bytes of this instruction (length indicated by @size above)
        this.bytes = [];
        for (var i = 0; i < this.size; i++) {
            var byteValue = mCapstone.getValue(pointer + 18 + i, 'i8');
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
        var detail = {
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
        var detail_addr = mCapstone.getValue(pointer + 228, '*');
        if (detail_addr != 0) {
            // Architecture-agnostic instruction info
            detail.regs_read = [];
            var regs_read_count = mCapstone.getValue(detail_addr + 12, 'i8');
            for (var i = 0; i < regs_read_count; i++) {
                detail.regs_read[i] = mCapstone.getValue(detail_addr + 0 + i, 'i8');
            }
            detail.regs_write = [];
            var regs_write_count = mCapstone.getValue(detail_addr + 33, 'i8');
            for (var i = 0; i < regs_write_count; i++) {
                detail.regs_write[i] = mCapstone.getValue(detail_addr + 13 + i, 'i8');
            }
            detail.groups = [];
            var groups_count = mCapstone.getValue(detail_addr + 42, 'i8');
            for (var i = 0; i < groups_count; i++) {
                detail.groups[i] = mCapstone.getValue(detail_addr + 34 + i, 'i8');
            }
            // Architecture-specific instruction info
            var arch_info_addr = detail_addr + 44;
            var op_size = void 0;
            var op_count = void 0;
            switch (arch) {
                case 0 /* ARCH_ARM */:
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
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 0x24 + (i * op_size);
                        op.vector_index = mCapstone.getValue(op_addr + 0, 'i32');
                        op.shift = {
                            type: mCapstone.getValue(op_addr + 4, 'i32'),
                            value: mCapstone.getValue(op_addr + 8, 'i32')
                        };
                        op.type = mCapstone.getValue(op_addr + 12, 'i32');
                        switch (op.type) {
                            case 1 /* ARM_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 16, 'i32');
                                break;
                            case 2 /* ARM_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 16, 'i32');
                                break;
                            case 4 /* ARM_OP_FP */:
                                op.fp = mCapstone.getValue(op_addr + 16, 'double');
                                break;
                            case 66 /* ARM_OP_SETEND */:
                                op.setend = mCapstone.getValue(op_addr + 16, 'i32');
                                break;
                            case 3 /* ARM_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 16, 'i32'),
                                    index: mCapstone.getValue(op_addr + 20, 'i32'),
                                    scale: mCapstone.getValue(op_addr + 24, 'i32'),
                                    disp: mCapstone.getValue(op_addr + 28, 'i32')
                                };
                                break;
                        }
                        op.subtracted = Boolean(mCapstone.getValue(arch_info_addr + 32, 'i8'));
                        detail.op[i] = op;
                    }
                    break;
                case 1 /* ARCH_ARM64 */:
                    detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                    detail.update_flags = Boolean(mCapstone.getValue(arch_info_addr + 0x04, 'i8'));
                    detail.writeback = Boolean(mCapstone.getValue(arch_info_addr + 0x05, 'i8'));
                    // Operands
                    op_size = 40;
                    op_count = mCapstone.getValue(arch_info_addr + 0x06, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 0x08 + (i * op_size);
                        op.vector_index = mCapstone.getValue(op_addr + 0, 'i32');
                        op.vas = mCapstone.getValue(op_addr + 4, 'i32');
                        op.vess = mCapstone.getValue(op_addr + 8, 'i32');
                        op.shift = {
                            type: mCapstone.getValue(op_addr + 12, 'i32'),
                            value: mCapstone.getValue(op_addr + 16, 'i32')
                        };
                        op.ext = mCapstone.getValue(op_addr + 20, 'i32');
                        op.type = mCapstone.getValue(op_addr + 24, 'i32');
                        switch (op.type) {
                            case 1 /* ARM64_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 28, 'i32');
                                break;
                            case 2 /* ARM64_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 28, 'i64');
                                break;
                            case 4 /* ARM64_OP_FP */:
                                op.fp = mCapstone.getValue(op_addr + 28, 'double');
                                break;
                            case 67 /* ARM64_OP_PSTATE */:
                                op.pstate = mCapstone.getValue(op_addr + 28, 'i32');
                                break;
                            case 68 /* ARM64_OP_SYS */:
                                op.sys = mCapstone.getValue(op_addr + 28, 'i32');
                                break;
                            case 70 /* ARM64_OP_BARRIER */:
                                op.barrier = mCapstone.getValue(op_addr + 28, 'i32');
                                break;
                            case 69 /* ARM64_OP_PREFETCH */:
                                op.prefetch = mCapstone.getValue(op_addr + 28, 'i32');
                                break;
                            case 3 /* ARM64_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 28, 'i32'),
                                    index: mCapstone.getValue(op_addr + 32, 'i32'),
                                    disp: mCapstone.getValue(op_addr + 36, 'i32')
                                };
                                break;
                        }
                        detail.op[i] = op;
                    }
                    break;
                case 2 /* ARCH_MIPS */:
                    // Operands
                    op_size = 16;
                    op_count = mCapstone.getValue(arch_info_addr + 0x00, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
                            type: 0,
                            reg: 0,
                            imm: 0,
                            mem: {
                                base: 0,
                                disp: 0
                            }
                        };
                        var op_addr = arch_info_addr + 0x04 + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* MIPS_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* MIPS_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i64');
                                break;
                            case 3 /* MIPS_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 4, 'i32'),
                                    disp: mCapstone.getValue(op_addr + 8, 'i64')
                                };
                                break;
                        }
                        detail.op[i] = op;
                    }
                    break;
                case 3 /* ARCH_X86 */:
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
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 0x30 + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* X86_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* X86_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i64');
                                break;
                            case 4 /* X86_OP_FP */:
                                op.fp = mCapstone.getValue(op_addr + 4, 'double');
                                break;
                            case 3 /* X86_OP_MEM */:
                                op.mem = {
                                    segment: mCapstone.getValue(op_addr + 4, 'i32'),
                                    base: mCapstone.getValue(op_addr + 8, 'i32'),
                                    index: mCapstone.getValue(op_addr + 12, 'i32'),
                                    scale: mCapstone.getValue(op_addr + 16, 'i32'),
                                    disp: mCapstone.getValue(op_addr + 20, 'i64')
                                };
                                break;
                        }
                        op.size = mCapstone.getValue(op_addr + 28, 'i8');
                        op.avx_bcast = mCapstone.getValue(op_addr + 32, 'i32');
                        op.avx_zero_opmask = mCapstone.getValue(op_addr + 36, 'i8');
                        detail.op[i] = op;
                    }
                    break;
                case 4 /* ARCH_PPC */:
                    detail.bc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                    detail.bh = mCapstone.getValue(arch_info_addr + 0x04, 'i32');
                    detail.update_cr0 = mCapstone.getValue(arch_info_addr + 0x08, 'i8');
                    // Operands
                    op_size = 16;
                    op_count = mCapstone.getValue(arch_info_addr + 0x09, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 0x0C + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* PPC_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* PPC_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 64 /* PPC_OP_CRX */:
                                op.crx = {
                                    scale: mCapstone.getValue(op_addr + 4, 'i32'),
                                    reg: mCapstone.getValue(op_addr + 8, 'i32'),
                                    cond: mCapstone.getValue(op_addr + 12, 'i32')
                                };
                                break;
                            case 3 /* PPC_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 4, 'i32'),
                                    disp: mCapstone.getValue(op_addr + 8, 'i32')
                                };
                                break;
                        }
                        detail.op[i] = op;
                    }
                    break;
                case 5 /* ARCH_SPARC */:
                    detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                    detail.hint = mCapstone.getValue(arch_info_addr + 0x04, 'i32');
                    // Operands
                    op_size = 12;
                    op_count = mCapstone.getValue(arch_info_addr + 0x08, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
                            type: 0,
                            reg: 0,
                            imm: 0,
                            mem: {
                                base: 0,
                                index: 0,
                                disp: 0
                            }
                        };
                        var op_addr = arch_info_addr + 0x09 + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* SPARC_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* SPARC_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 3 /* SPARC_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 4, 'i8'),
                                    index: mCapstone.getValue(op_addr + 5, 'i8'),
                                    disp: mCapstone.getValue(op_addr + 8, 'i32')
                                };
                                break;
                        }
                        detail.op[i] = op;
                    }
                    break;
                case 6 /* ARCH_SYSZ */:
                    detail.cc = mCapstone.getValue(arch_info_addr + 0x00, 'i32');
                    // Operands
                    op_size = 24;
                    op_count = mCapstone.getValue(arch_info_addr + 0x04, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 0x08 + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* SYSZ_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* SYSZ_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 3 /* SYSZ_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 4, 'i8'),
                                    index: mCapstone.getValue(op_addr + 5, 'i8'),
                                    length: mCapstone.getValue(op_addr + 8, 'i64'),
                                    disp: mCapstone.getValue(op_addr + 16, 'i64')
                                };
                                break;
                        }
                        detail.op[i] = op;
                    }
                    break;
                case 7 /* ARCH_XCORE */:
                    // Operands
                    op_size = 16;
                    op_count = mCapstone.getValue(arch_info_addr + 0, 'i8');
                    for (var i = 0; i < op_count; i++) {
                        var op = {
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
                        var op_addr = arch_info_addr + 4 + (i * op_size);
                        op.type = mCapstone.getValue(op_addr + 0, 'i32');
                        switch (op.type) {
                            case 1 /* XCORE_OP_REG */:
                                op.reg = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 2 /* XCORE_OP_IMM */:
                                op.imm = mCapstone.getValue(op_addr + 4, 'i32');
                                break;
                            case 3 /* XCORE_OP_MEM */:
                                op.mem = {
                                    base: mCapstone.getValue(op_addr + 4, 'i8'),
                                    index: mCapstone.getValue(op_addr + 5, 'i8'),
                                    disp: mCapstone.getValue(op_addr + 8, 'i32'),
                                    direct: mCapstone.getValue(op_addr + 12, 'i32')
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
    cs.Capstone = function (arch, mode) {
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = mCapstone._malloc(4);
        // Options
        this.option = function (option, value) {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            if (!handle) {
                return;
            }
            var ret = mCapstone.ccall('cs_option', 'number', ['pointer', 'number', 'number'], [handle, option, value]);
            if (ret != 0 /* ERR_OK */) {
                var error = 'Capstone.js: Function cs_option failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
        };
        // Disassemble
        this.disasm = function (buffer, addr, max) {
            var handle = mCapstone.getValue(this.handle_ptr, 'i32');
            // Allocate buffer and copy data
            var buffer_len = buffer.length;
            var buffer_ptr = mCapstone._malloc(buffer_len);
            mCapstone.writeArrayToMemory(buffer, buffer_ptr);
            // Pointer to the instruction array
            var insn_ptr_ptr = mCapstone._malloc(4);
            var count = mCapstone.ccall('cs_disasm', 'number', ['number', 'pointer', 'number', 'number', 'number', 'pointer'], [handle, buffer_ptr, buffer_len, addr, 0, max || 0, insn_ptr_ptr]);
            if (count == 0 && buffer_len != 0) {
                mCapstone._free(insn_ptr_ptr);
                mCapstone._free(buffer_ptr);
                var code = this.errno();
                var error = 'Capstone.js: Function cs_disasm failed with code ' + code + ':\n' + cs.strerror(code);
                throw error;
            }
            // Dereference intruction array
            var insn_ptr = mCapstone.getValue(insn_ptr_ptr, 'i32');
            var insn_size = 232;
            var instructions = [];
            // Save instructions
            for (var i = 0; i < count; i++) {
                instructions.push(new cs.Instruction(insn_ptr + i * insn_size, this.arch));
            }
            count = mCapstone.ccall('cs_free', 'void', ['pointer', 'number'], [insn_ptr, count]);
            mCapstone._free(insn_ptr_ptr);
            mCapstone._free(buffer_ptr);
            return instructions;
        };
        this.reg_name = function (reg_id) {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            var ret = mCapstone.ccall('cs_reg_name', 'string', ['pointer', 'number'], [handle, reg_id]);
            return ret;
        };
        this.insn_name = function (insn_id) {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            var ret = mCapstone.ccall('cs_insn_name', 'string', ['pointer', 'number'], [handle, insn_id]);
            return ret;
        };
        this.group_name = function (group_id) {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            var ret = mCapstone.ccall('cs_group_name', 'string', ['pointer', 'number'], [handle, group_id]);
            return ret;
        };
        this.errno = function () {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            var ret = mCapstone.ccall('cs_errno', 'number', ['pointer'], [handle]);
            return ret;
        };
        this.close = function () {
            var handle = mCapstone.getValue(this.handle_ptr, '*');
            var ret = mCapstone.ccall('cs_close', 'number', ['pointer'], [handle]);
            if (ret != 0 /* ERR_OK */) {
                var error = 'Capstone.js: Function cs_close failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
            mCapstone._free(this.handle_ptr);
        };
        // Constructor
        var ret = mCapstone.ccall('cs_open', 'number', ['number', 'number', 'pointer'], [this.arch, this.mode, this.handle_ptr]);
        if (ret != 0 /* ERR_OK */) {
            mCapstone.setValue(this.handle_ptr, 0, '*');
            var error = 'Capstone.js: Function cs_open failed with code ' + ret + ':\n' + cs.strerror(ret);
            throw error;
        }
    };
})(cs || (cs = {}));
