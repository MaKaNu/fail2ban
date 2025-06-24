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

import json
import re
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class JSONParser:
    """
    JSON Parser for fail2ban filters.
    
    This class provides JSON parsing capabilities for structured log output,
    allowing fail2ban to work with JSON-formatted logs from modern applications.
    """
    
    def __init__(self, json_paths=None, json_ignore_paths=None):
        """
        Initialize JSON parser.
        
        Args:
            json_paths: List of JSONPath expressions to extract data
            json_ignore_paths: List of JSONPath expressions for ignore conditions
        """
        self.json_paths = json_paths or []
        self.json_ignore_paths = json_ignore_paths or []
        self._compiled_paths = []
        self._compiled_ignore_paths = []
        self._compile_paths()
    
    def _compile_paths(self):
        """Compile JSONPath expressions for better performance."""
        for path in self.json_paths:
            try:
                # Simple JSONPath-like syntax support
                # Supports: $.field, $.field.subfield, $['field'], $[0], etc.
                compiled = self._compile_jsonpath(path)
                self._compiled_paths.append(compiled)
            except Exception as e:
                logSys.error("Invalid JSONPath expression '%s': %s", path, e)
        
        for path in self.json_ignore_paths:
            try:
                compiled = self._compile_jsonpath(path)
                self._compiled_ignore_paths.append(compiled)
            except Exception as e:
                logSys.error("Invalid JSON ignore path expression '%s': %s", path, e)
    
    def _compile_jsonpath(self, path):
        """
        Compile a JSONPath expression into a function.
        
        Supports basic JSONPath syntax:
        - $.field
        - $.field.subfield
        - $['field']
        - $[0]
        - $.field[0]
        """
        if not path.startswith('$'):
            raise ValueError("JSONPath must start with $")
        
        # Remove leading $
        path = path[1:]
        
        # Split by dots and brackets
        parts = re.split(r'([.\[\]])', path)
        parts = [p for p in parts if p.strip()]
        
        def extract(data):
            """Extract value from data using compiled path."""
            current = data
            
            i = 0
            while i < len(parts):
                part = parts[i].strip()
                
                if part == '.':
                    # Next part is a field name
                    if i + 1 >= len(parts):
                        raise ValueError("Unexpected end after dot")
                    field = parts[i + 1].strip()
                    if not field:
                        raise ValueError("Empty field name after dot")
                    current = current.get(field)
                    i += 2
                
                elif part == '[':
                    # Next part is an index or quoted field name
                    if i + 2 >= len(parts) or parts[i + 2] != ']':
                        raise ValueError("Unclosed bracket")
                    
                    key_part = parts[i + 1].strip()
                    
                    if key_part.startswith("'") and key_part.endswith("'"):
                        # Quoted field name: $['field']
                        field = key_part[1:-1]
                        current = current.get(field)
                    elif key_part.startswith('"') and key_part.endswith('"'):
                        # Double-quoted field name: $["field"]
                        field = key_part[1:-1]
                        current = current.get(field)
                    else:
                        # Numeric index: $[0]
                        try:
                            index = int(key_part)
                            if isinstance(current, list):
                                current = current[index] if index < len(current) else None
                            else:
                                current = None
                        except ValueError:
                            raise ValueError(f"Invalid index: {key_part}")
                    
                    i += 3  # Skip [, key, ]
                
                else:
                    # Direct field access (first part)
                    current = current.get(part)
                    i += 1
                
                if current is None:
                    return None
            
            return current
        
        return extract
    
    def parse_line(self, line):
        """
        Parse a JSON log line and extract relevant data.
        
        Args:
            line: JSON log line as string
            
        Returns:
            dict: Extracted data or None if parsing failed
        """
        try:
            # Parse JSON
            data = json.loads(line.strip())
            
            # Check ignore conditions first
            if self._should_ignore(data):
                return None
            
            # Extract data using JSONPath expressions
            extracted = {}
            for i, path_func in enumerate(self._compiled_paths):
                try:
                    value = path_func(data)
                    if value is not None:
                        extracted[f'json_field_{i}'] = str(value)
                except Exception as e:
                    logSys.debug("Error extracting JSONPath %s: %s", self.json_paths[i], e)
            
            return extracted
            
        except json.JSONDecodeError as e:
            logSys.debug("Failed to parse JSON line: %s", e)
            return None
        except Exception as e:
            logSys.debug("Error parsing JSON line: %s", e)
            return None
    
    def _should_ignore(self, data):
        """
        Check if data should be ignored based on ignore paths.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            bool: True if should be ignored
        """
        for path_func in self._compiled_ignore_paths:
            try:
                value = path_func(data)
                if value is not None:
                    # If any ignore path returns a value, ignore this line
                    return True
            except Exception:
                # If ignore path fails, don't ignore
                pass
        
        return False
    
    def extract_host(self, data):
        """
        Extract host information from parsed JSON data.
        
        Args:
            data: Parsed JSON data from parse_line()
            
        Returns:
            str: Host IP/name or None
        """
        # Common host field names
        host_fields = ['host', 'ip', 'client_ip', 'remote_addr', 'source_ip', 'address']
        
        for field in host_fields:
            if field in data:
                return data[field]
        
        return None
    
    def extract_user(self, data):
        """
        Extract user information from parsed JSON data.
        
        Args:
            data: Parsed JSON data from parse_line()
            
        Returns:
            str: Username or None
        """
        # Common user field names
        user_fields = ['user', 'username', 'login', 'account', 'auth_user']
        
        for field in user_fields:
            if field in data:
                return data[field]
        
        return None


class JSONRegex:
    """
    JSON-aware regex matcher that can work with extracted JSON data.
    """
    
    def __init__(self, regex_pattern, json_parser=None):
        """
        Initialize JSON regex matcher.
        
        Args:
            regex_pattern: Regular expression pattern
            json_parser: JSONParser instance for JSON data extraction
        """
        self.regex_pattern = regex_pattern
        self.json_parser = json_parser
        self._compiled_regex = re.compile(regex_pattern, re.MULTILINE)
    
    def match(self, line):
        """
        Match line against regex pattern, with JSON support.
        
        Args:
            line: Log line to match
            
        Returns:
            dict: Match groups or None if no match
        """
        # Try JSON parsing first if parser is available
        if self.json_parser:
            json_data = self.json_parser.parse_line(line)
            if json_data:
                # Create a pseudo-line from JSON data for regex matching
                json_line = " ".join([f"{k}={v}" for k, v in json_data.items()])
                
                # Try matching against JSON-extracted data
                match = self._compiled_regex.search(json_line)
                if match:
                    groups = match.groupdict()
                    # Add JSON data to groups
                    groups.update(json_data)
                    return groups
        
        # Fall back to direct regex matching
        match = self._compiled_regex.search(line)
        if match:
            return match.groupdict()
        
        return None 