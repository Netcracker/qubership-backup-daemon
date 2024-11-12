# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from storage import Storage
from shutil import rmtree
import os


class StorageTests(unittest.TestCase):
	storage_root = "tests-temp"
	
	def cleanup(self):
		print(f'Cleanup storage: {self.storage_root}')
		if os.path.exists(self.storage_root):
			rmtree(self.storage_root)
			
	def setUp(self):
		self.cleanup()
		
	def tearDown(self):
		self.cleanup()
	
	def test_normal_case(self):
		storage = Storage(self.storage_root)
		with storage.open_vault() as s:
			print(f'Do something with: {str(s)}')
			
		self.assertEqual(1, len(storage.list()))
		
	def test_exc_case(self):
		storage = Storage(self.storage_root)
		try:
			with storage.open_vault():
				raise TestException("Suppose something wrong happens while process backup")
		except TestException:
			self.assertEqual(1, len(storage.list()))
			self.assertTrue(storage.list()[0].to_json()["failed"], "Vault should be locked")
	
	def test_metrics_get_from_vault_in_use(self):
		storage = Storage(self.storage_root)
		with storage.open_vault():
			self.assertEqual(0, len(storage.list()), "No vault is done yet, so array is empty")
		
		self.assertEqual(1, len(storage.list()), "One vault should be done")


class TestException(Exception):
	pass
