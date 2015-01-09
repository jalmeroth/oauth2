#!/usr/bin/python
import unittest
from request import WebRequest

class TestWebRequest(unittest.TestCase):
	"""docstring for TestWebRequest"""
	def setUp(self):
		"""docstring for setUp"""
		self.r = WebRequest()
		url = "http://www.almeroth.com"
		self.getResult = self.r.get(url)
	
	def test_func_get(self):
		"""docstring for test_func_get"""
		needle = "Jan Almeroth"
		self.assertTrue(needle in self.getResult.text)
	
	def test_func_get_status_code(self):
		"""docstring for test_func_get_status_code"""
		self.assertEqual(200, self.getResult.status_code)

if __name__ == '__main__':
	unittest.main()