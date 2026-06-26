#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

#include "cfnat.c"

static jmp_buf jump_buffer;

static void signal_handler(int sig) {
    (void)sig;
    longjmp(jump_buffer, 1);
}

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "cloudflaremirrors.com/debian",  // Valid input (exact size)
        "cloudflaremirrors.com/debian-extra-long-payload-that-exceeds-buffer",  // Exploit case (2x+ size)
        "A",  // Boundary case (minimal)
        "very-long-string-1234567890-1234567890-1234567890-1234567890-1234567890-1234567890",  // 10x size
        ""  // Empty string
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        Config c;
        struct sigaction sa, old_sa;
        
        // Set up signal handler for SIGSEGV/SIGABRT
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        
        sigaction(SIGSEGV, &sa, &old_sa);
        sigaction(SIGABRT, &sa, NULL);
        
        if (setjmp(jump_buffer) == 0) {
            // This should not cause buffer overflow
            cfg_defaults(&c);
            
            // Test with adversarial payloads by modifying the default strings
            // We'll test the actual strcpy pattern by temporarily replacing DEFAULT_BAIDU_DOMAIN
            char *original_domain = DEFAULT_BAIDU_DOMAIN;
            // Cast away const to simulate adversarial input
            *(char**)&DEFAULT_BAIDU_DOMAIN = (char*)payloads[i];
            
            // Create fresh config and call cfg_defaults
            Config c2;
            cfg_defaults(&c2);
            
            // Restore original
            *(char**)&DEFAULT_BAIDU_DOMAIN = original_domain;
            
            // Verify baidu_domain field doesn't exceed expected size
            ck_assert_msg(strlen(c2.baidu_domain) < sizeof(c2.baidu_domain),
                         "Buffer overflow detected with payload: %s", payloads[i]);
        } else {
            // Signal caught - test fails
            ck_abort_msg("Buffer overflow (crash) detected with payload: %s", payloads[i]);
        }
        
        // Restore original signal handler
        sigaction(SIGSEGV, &old_sa, NULL);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}