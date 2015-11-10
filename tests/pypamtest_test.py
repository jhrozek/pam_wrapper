#!/usr/bin/env python

import unittest
import os
import sys
import os.path

class PyPamTestCase(unittest.TestCase):
    def assertPamTestResultEqual(self, test_result, err_list, info_list):
        self.assertTrue(test_result != None)
        self.assertTrue(hasattr(test_result, 'info'))
        self.assertTrue(hasattr(test_result, 'errors'))
        self.assertSequenceEqual(test_result.info, err_list)
        self.assertSequenceEqual(test_result.errors, info_list)

class PyPamTestImport(unittest.TestCase):
    def setUp(self):
        " Make sure we load the in-tree module "
        self.modpath = os.path.join(os.getcwd(), "../src/python")
        self.system_path = sys.path[:]
        sys.path = [ self.modpath ]

    def tearDown(self):
        " Restore the system path "
        sys.path = self.system_path

    def testImport(self):
        " Import the module "
        try:
            import pypamtest
        except ImportError as e:
            print("Could not load the pypamtest module from %s. Please check if it is compiled" % self.modpath)
            raise e

class PyPamTestTestCase(unittest.TestCase):
    def test_constants(self):
        " Tests the enum was added correctly "
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_AUTHENTICATE'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_SETCRED'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_ACCOUNT'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_OPEN_SESSION'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_CLOSE_SESSION'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_CHAUTHTOK'))

        self.assertTrue(hasattr(pypamtest, 'PAMTEST_GETENVLIST'))
        self.assertTrue(hasattr(pypamtest, 'PAMTEST_KEEPHANDLE'))

    def test_members(self):
        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE)
        self.assertEqual(tc.pam_operation, pypamtest.PAMTEST_AUTHENTICATE)
        self.assertEqual(tc.expected_rv, 0)     # PAM_SUCCESS
        self.assertEqual(tc.flags, 0)

        tc = pypamtest.TestCase(pypamtest.PAMTEST_CHAUTHTOK, 1, 2)
        self.assertEqual(tc.pam_operation, pypamtest.PAMTEST_CHAUTHTOK)
        self.assertEqual(tc.expected_rv, 1)
        self.assertEqual(tc.flags, 2)

        # Testcase members should be immutable after constructing the test
        # case
#        with self.assertRaises(AttributeError):
#            tc.pam_operation = pypamtest.PAMTEST_AUTHENTICATE
#
#        with self.assertRaises(AttributeError):
#            tc.expected_rv = 2
#
#        with self.assertRaises(AttributeError):
#            tc.flags = 3

    def test_bad_op(self):
        self.assertRaises(ValueError, pypamtest.TestCase, 666)

# These are not silly tests. They test setup of the object and proper
# GC function
class PyPamTestTestResult(PyPamTestCase):
    def setUp(self):
        self.list_info = [ "info", "list" ]
        self.list_error = [ "error", "list" ]

    def test_default(self):
        res = pypamtest.TestResult()
        self.assertPamTestResultEqual(res, [], [])

    def test_set_both(self):
        res = pypamtest.TestResult(self.list_info,
                                   self.list_error)
        self.assertPamTestResultEqual(res,
                                      self.list_info,
                                      self.list_error)

    def test_repr_default(self):
        res = pypamtest.TestResult()
        self.assertEqual(repr(res), "{ errors: {  } infos: {  } }")

    def test_repr_both(self):
        res = pypamtest.TestResult(self.list_info,
                                   self.list_error)
        self.assertEqual(repr(res),
                         "{ errors: { {info}{list} } infos: { {info}{list} } }")

class PyPamTestRunTest(unittest.TestCase):
    def test_run(self):
        neo_password = "secret"
        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE)
        res = pypamtest.run_pamtest("neo", "matrix_py", [tc], [ neo_password ])

        # No messages from this test -> both info and err should be empty tuples
        self.assertTrue(res != None)
        self.assertTrue(hasattr(res, 'info'))
        self.assertTrue(hasattr(res, 'errors'))
        # Running with verbose mode so there would be an info message
        self.assertSequenceEqual(res.info, (u'Authentication succeeded',))
        self.assertSequenceEqual(res.errors, ())

    def test_repr(self):
        tc = pypamtest.TestCase(pypamtest.PAMTEST_CHAUTHTOK, 1, 2)
        r = repr(tc)
        self.assertEqual(r, "{ pam_operation [5] expected_rv [1] flags [2] }")

    def test_exception(self):
        neo_password = "wrong_secret"
        tc = pypamtest.TestCase(pypamtest.PAMTEST_AUTHENTICATE)

        self.assertRaisesRegexp(pypamtest.PamTestError,
                                "Error \[2\]: Test case { pam_operation \[0\] "
                                "expected_rv \[0\] flags \[0\] } "
                                "retured \[7\]",
                                pypamtest.run_pamtest,
                                "neo", "matrix_py", [tc], [ neo_password ])

if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(PyPamTestImport)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1
        # need to bail out here because module could not be imported
        sys.exit(error)

    sys.path.insert(0, os.path.join(os.getcwd()))
    import pypamtest

    suite = unittest.TestLoader().loadTestsFromTestCase(PyPamTestTestCase)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    suite = unittest.TestLoader().loadTestsFromTestCase(PyPamTestTestResult)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x3

    suite = unittest.TestLoader().loadTestsFromTestCase(PyPamTestRunTest)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x4

    sys.exit(error)
