# Copyright 2017 Xaptum, Inc.
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

if (NOT TARGET ecdaa)
        if (NOT ECDAA_LOCAL_DIR)
                set(ECDAA_LOCAL_DIR "${CMAKE_CURRENT_LIST_DIR}/../ecdaa/build")
        endif (NOT ECDAA_LOCAL_DIR)

        if (NOT FORCE_SYSTEM_ECDAA_LIB)
                set(ECDAA_INCLUDE_DIRS "${ECDAA_LOCAL_DIR}/include/")
                set(ECDAA_LIB_DIRS "${ECDAA_LOCAL_DIR}/")
        endif (NOT FORCE_SYSTEM_ECDAA_LIB)

        find_library(ECDAA_LIBRARY
                     NAMES ecdaa ecdaa_static
                     HINTS ${ECDAA_LIB_DIRS})
        set(ECDAA_LIBRARIES ${ECDAA_LIBRARY})

        set(ECDAA_FOUND TRUE)
endif (NOT TARGET ecdaa)
