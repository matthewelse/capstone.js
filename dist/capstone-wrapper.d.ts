export declare namespace cs {
    const version: () => any;
    const support: (query: any) => any;
    const strerror: (code: any) => any;
    /**
     * Instruction object
     */
    const Instruction: (pointer: any, arch: any) => void;
    /**
     * Capstone object
     */
    const Capstone: (arch: any, mode: any) => void;
}
