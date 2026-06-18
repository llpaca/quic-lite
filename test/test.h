#ifndef QL_TEST_H
#define QL_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int ql_tests_run;

#define TEST(name) static void name(void)

#define RUN_TEST(test)                                      \
    do {                                                    \
        printf("[ RUN ] %s\n", #test);                      \
        test();                                             \
        ql_tests_run++;                                     \
        printf("[ PASS] %s\n", #test);                      \
    } while (0)

#define FAIL(msg)                                           \
    do {                                                    \
        fprintf(stderr,                                     \
                "\n[FAIL] %s:%d: %s\n",                     \
                __FILE__,                                   \
                __LINE__,                                   \
                msg);                                       \
        exit(EXIT_FAILURE);                                 \
    } while (0)

#define EXPECT(cond)                                        \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr,                                 \
                    "\n[FAIL] %s:%d\n",                     \
                    __FILE__,                               \
                    __LINE__);                              \
            fprintf(stderr,                                 \
                    "       EXPECT(%s)\n",                  \
                    #cond);                                 \
            exit(EXIT_FAILURE);                             \
        }                                                   \
    } while (0)

#define EXPECT_EQ(a, b) EXPECT((a) == (b))
#define EXPECT_NE(a, b) EXPECT((a) != (b))
#define EXPECT_LT(a, b) EXPECT((a) <  (b))
#define EXPECT_LE(a, b) EXPECT((a) <= (b))
#define EXPECT_GT(a, b) EXPECT((a) >  (b))
#define EXPECT_GE(a, b) EXPECT((a) >= (b))

static inline void ql_test_summary(void)
{
    printf("\n=====================================\n");
    printf("All tests passed (%d test groups)\n",
           ql_tests_run);
    printf("=====================================\n");
}

#endif