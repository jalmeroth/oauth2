#!/usr/bin/python
import unittest
from auth import Auth

class TestAuth(unittest.TestCase):
    """docstring for TestAuth"""
    
    def setUp(self):
        """docstring for setUp"""
        auth = Auth()

if __name__ == '__main__':
    unittest.main()