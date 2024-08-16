void restore_breakpoint(uint64_t address) {
    auto it = breakpoints.find(address);
    if (it == breakpoints.end()) {
        cerr << "No breakpoint set at this address: " << hex << address << dec << endl;
        return;
    }

    uint8_t original_byte = it->second.second;
    long current_data = ptrace(PTRACE_PEEKTEXT, pid, address, nullptr);
    long restored_data = (current_data & ~0xFF) | original_byte;

    ptrace(PTRACE_POKETEXT, pid, address, restored_data);
}

void apply_breakpoint(uint64_t address) {
    auto it = breakpoints.find(address);
    if (it != breakpoints.end()) {
        uint8_t original_byte = it->second.second;
        long int3 = (original_byte & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid, address, int3);
    }
}