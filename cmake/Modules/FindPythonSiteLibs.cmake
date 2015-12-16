#.rst:
# FindPythonSiteLibs
# --------------
#
# Find the location of python site libraries
#
# ::
#
# PYTHON_SITELIB        = path to the sitelib install directory
# PYTHON_SITEINC        = path to the siteinc install directory
#
# Note that these variable do not have a prefix set. So you should for example
# prepend the CMAKE_INSTALL_PREFIX.

#=============================================================================
# Copyright 2015      Andreas Schneider <asn@cryptomilk.org>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distribute this file outside of CMake, substitute the full
#  License text for the above reference.)

if (PYTHON_EXECUTABLE)
    ### PYTHON_SITELIB
    execute_process(
        COMMAND
        ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(plat_specific=True, prefix=''))"
        OUTPUT_VARIABLE
            PYTHON_SITELIB_OUTPUT_VARIABLE
        RESULT_VARIABLE
            PYTHON_SITELIB_RESULT_VARIABLE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT PYTHON_SITELIB_RESULT_VARIABLE)
        file(TO_CMAKE_PATH "${PYTHON_SITELIB_OUTPUT_VARIABLE}" PYTHON_SITELIB)
    endif ()

    ### PYTHON_SITEINC
    execute_process(
        COMMAND
            ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_inc; print(get_python_inc(plat_specific=True, prefix=''))"
        OUTPUT_VARIABLE
            PYTHON_SITEINC_OUTPUT_VARIABLE
        RESULT_VARIABLE
            PYTHON_SITEINC_RESULT_VARIABLE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT PYTHON_SITEINC_RESULT_VARIABLE)
        file(TO_CMAKE_PATH "${PYTHON_SITEINC_OUTPUT_VARIABLE}" PYTHON_SITEINC)
    endif ()
endif (PYTHON_EXECUTABLE)
