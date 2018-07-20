/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#define TEST_ASSERT(cond) \
    do \
    { \
        if (!(cond)) { \
            printf("Condition \'%s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #cond,__FILE__,  __func__, __LINE__); \
            printf("exiting\n"); \
            exit(1); \
        } \
    } while(0)

#define EXPECT_EQ(arg1, arg2) \
    do \
    { \
        if (arg1 != arg2) { \
            printf("Condition \'%s == %s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #arg1, #arg2,__FILE__,  __func__, __LINE__); \
            printf("exiting\n"); \
            exit(1); \
        } \
    } while(0)

#define EXPECT_NE(arg1, arg2) \
    do \
    { \
        if (arg1 == arg2) { \
            printf("Condition \'%s != %s\' failed\n\tin file: \'%s\'\n\tin function: \'%s\'\n\tat line: %d\n", #arg1, #arg2,__FILE__,  __func__, __LINE__); \
            printf("exiting\n"); \
            exit(1); \
        } \
    } while(0)
