/* Replacement for the unsafe dispatch/hash-check portion of upstream python.c.
 * call_Py_Main below is retained from upstream. Bootstrap uses stock CPython;
 * the deployable interpreter never exposes build bypasses or arbitrary -c/-m.
 */
static int call_Py_Main(int argc, char **argv);

static int verify_program(const char *path, const char *expected) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("verified program"); return 0; }
    SHA256_CTX ctx;
    unsigned char buf[HASH_BUF_LEN], digest[SHA256_DIGEST_LENGTH];
    size_t n;
    if (SHA256_Init(&ctx) != 1) { fclose(f); return 0; }
    while ((n = fread(buf, 1, sizeof(buf), f)) != 0)
        if (SHA256_Update(&ctx, buf, n) != 1) { fclose(f); return 0; }
    if (ferror(f) || SHA256_Final(digest, &ctx) != 1) { fclose(f); return 0; }
    if (fclose(f) != 0) return 0;
    char actual[65];
    for (size_t i = 0; i < sizeof(digest); ++i) snprintf(actual + i*2, 3, "%02x", digest[i]);
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "Verified program digest mismatch: %s\n", path);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *program = DP_PROGRAM, *digest = DP_HASH_VALUE;
    if (argc == 2 && strcmp(argv[1], "-gencert") == 0) {
        program = GEN_CERT_PROGRAM; digest = GCP_HASH_VALUE;
    } else if (!(argc == 1 || (argc == 2 && strcmp(argv[1], DP_PROGRAM) == 0))) {
        fprintf(stderr, "Only the fixed, measured application may execute\n");
        return 2;
    }
    if (!verify_program(program, digest)) return 3;
    char *fixed_argv[] = {argv[0], (char *)program, NULL};
    return call_Py_Main(2, fixed_argv);
}
