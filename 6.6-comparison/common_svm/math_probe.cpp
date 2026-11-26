// Diagnostic dispatch only; both modes use the same compiled caller.
#include <cmath>
#include <cstring>
extern "C" double work2_probe_exp(double);
extern "C" {
double (*work2_exp_fn)(double) = exp;
static int selected_mode = 0;
int work2_math_select(int mode) {
    if (mode != 0 && mode != 1) return 0;
    selected_mode = mode;
    work2_exp_fn = mode ? work2_probe_exp : exp;
    return 1;
}
int work2_math_bytes(unsigned char* out) {
    if (!out) return -1;
    std::memcpy(out, reinterpret_cast<const void*>(exp), 64);
    std::memcpy(out+64, reinterpret_cast<const void*>(work2_probe_exp), 64);
    return selected_mode;
}
}
