# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

__author__ = "Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2024 Fail2Ban Contributors"
__license__ = "GPL"

import unittest
import sys
import os

# Add the parent directory to the path so we can import fail2ban modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fail2ban.server.jsonparser import JSONParser, JSONRegex


class JSONParserTestCase(unittest.TestCase):
    """Test cases for JSON parsing functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.parser = JSONParser(
            json_paths=['$.remote_addr', '$.method', '$.uri', '$.status'],
            json_ignore_paths=['$.status']
        )

    def test_basic_json_parsing(self):
        """Test basic JSON parsing functionality"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "POST", "uri": "/login", "status": 401}'
        
        result = self.parser.parse_line(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['json_field_0'], '192.168.1.100')
        self.assertEqual(result['json_field_1'], 'POST')
        self.assertEqual(result['json_field_2'], '/login')
        self.assertEqual(result['json_field_3'], '401')

    def test_nested_json_parsing(self):
        """Test parsing nested JSON structures"""
        parser = JSONParser(
            json_paths=['$.request.remote_addr', '$.request.method', '$.request.uri'],
            json_ignore_paths=[]
        )
        
        json_line = '{"request": {"remote_addr": "192.168.1.100", "method": "POST", "uri": "/login"}}'
        
        result = parser.parse_line(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['json_field_0'], '192.168.1.100')
        self.assertEqual(result['json_field_1'], 'POST')
        self.assertEqual(result['json_field_2'], '/login')

    def test_ignore_condition(self):
        """Test ignore conditions based on JSONPath"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "POST", "uri": "/login", "status": 200}'
        
        result = self.parser.parse_line(json_line)
        
        # Should be ignored because status is 200 (success)
        self.assertIsNone(result)

    def test_invalid_json(self):
        """Test handling of invalid JSON"""
        invalid_json = '{"remote_addr": "192.168.1.100", "method": "POST"'
        
        result = self.parser.parse_line(invalid_json)
        
        self.assertIsNone(result)

    def test_missing_fields(self):
        """Test handling of missing JSON fields"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "POST"}'
        
        result = self.parser.parse_line(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['json_field_0'], '192.168.1.100')
        self.assertEqual(result['json_field_1'], 'POST')
        # Missing fields should not be in result
        self.assertNotIn('json_field_2', result)
        self.assertNotIn('json_field_3', result)

    def test_array_access(self):
        """Test JSONPath array access"""
        parser = JSONParser(
            json_paths=['$.users[0].name', '$.users[1].name'],
            json_ignore_paths=[]
        )
        
        json_line = '{"users": [{"name": "user1"}, {"name": "user2"}]}'
        
        result = parser.parse_line(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['json_field_0'], 'user1')
        self.assertEqual(result['json_field_1'], 'user2')

    def test_quoted_field_names(self):
        """Test JSONPath with quoted field names"""
        parser = JSONParser(
            json_paths=['$["remote-addr"]', '$["user-name"]'],
            json_ignore_paths=[]
        )
        
        json_line = '{"remote-addr": "192.168.1.100", "user-name": "testuser"}'
        
        result = parser.parse_line(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['json_field_0'], '192.168.1.100')
        self.assertEqual(result['json_field_1'], 'testuser')

    def test_extract_host(self):
        """Test host extraction from parsed data"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "POST"}'
        
        result = self.parser.parse_line(json_line)
        host = self.parser.extract_host(result)
        
        self.assertEqual(host, '192.168.1.100')

    def test_extract_user(self):
        """Test user extraction from parsed data"""
        parser = JSONParser(
            json_paths=['$.user', '$.username'],
            json_ignore_paths=[]
        )
        
        json_line = '{"user": "testuser", "method": "POST"}'
        
        result = parser.parse_line(json_line)
        user = parser.extract_user(result)
        
        self.assertEqual(user, 'testuser')


class JSONRegexTestCase(unittest.TestCase):
    """Test cases for JSON-aware regex matching"""

    def setUp(self):
        """Set up test fixtures"""
        self.parser = JSONParser(
            json_paths=['$.remote_addr', '$.method', '$.uri', '$.status'],
            json_ignore_paths=[]
        )
        self.regex = JSONRegex(
            r'^json_field_0=<HOST> json_field_1=POST json_field_2=/login json_field_3=(401|403)$',
            self.parser
        )

    def test_json_regex_matching(self):
        """Test regex matching on JSON-extracted data"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "POST", "uri": "/login", "status": 401}'
        
        result = self.regex.match(json_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['host'], '192.168.1.100')

    def test_json_regex_no_match(self):
        """Test regex not matching on JSON-extracted data"""
        json_line = '{"remote_addr": "192.168.1.100", "method": "GET", "uri": "/login", "status": 401}'
        
        result = self.regex.match(json_line)
        
        self.assertIsNone(result)

    def test_fallback_to_direct_regex(self):
        """Test fallback to direct regex when JSON parsing fails"""
        regex = JSONRegex(r'^.*<HOST>.*$', None)
        
        line = 'Failed login from 192.168.1.100'
        
        result = regex.match(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['host'], '192.168.1.100')


class JSONPathCompilationTestCase(unittest.TestCase):
    """Test cases for JSONPath compilation"""

    def test_simple_field_access(self):
        """Test simple field access compilation"""
        parser = JSONParser(json_paths=['$.field'], json_ignore_paths=[])
        
        data = {'field': 'value'}
        result = parser._compiled_paths[0](data)
        
        self.assertEqual(result, 'value')

    def test_nested_field_access(self):
        """Test nested field access compilation"""
        parser = JSONParser(json_paths=['$.parent.child'], json_ignore_paths=[])
        
        data = {'parent': {'child': 'value'}}
        result = parser._compiled_paths[0](data)
        
        self.assertEqual(result, 'value')

    def test_array_access(self):
        """Test array access compilation"""
        parser = JSONParser(json_paths=['$.array[0]'], json_ignore_paths=[])
        
        data = {'array': ['first', 'second']}
        result = parser._compiled_paths[0](data)
        
        self.assertEqual(result, 'first')

    def test_quoted_field_access(self):
        """Test quoted field access compilation"""
        parser = JSONParser(json_paths=['$["field-name"]'], json_ignore_paths=[])
        
        data = {'field-name': 'value'}
        result = parser._compiled_paths[0](data)
        
        self.assertEqual(result, 'value')

    def test_invalid_jsonpath(self):
        """Test handling of invalid JSONPath expressions"""
        with self.assertRaises(ValueError):
            JSONParser(json_paths=['invalid_path'], json_ignore_paths=[])

    def test_missing_field_returns_none(self):
        """Test that missing fields return None"""
        parser = JSONParser(json_paths=['$.missing'], json_ignore_paths=[])
        
        data = {'existing': 'value'}
        result = parser._compiled_paths[0](data)
        
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main() 