JSON Parsing Support in Fail2Ban
================================

Overview
--------

Fail2Ban now supports JSON parsing for structured log output from modern applications.
This feature allows fail2ban to work with JSON-formatted logs without requiring complex
regex patterns that are fragile and difficult to maintain.

Features
--------

- **JSONPath Support**: Extract data from JSON logs using JSONPath expressions
- **Ignore Conditions**: Define JSONPath expressions to ignore certain log entries
- **Backward Compatibility**: Works alongside existing regex-based filters
- **Performance Optimized**: Compiled JSONPath expressions for efficient parsing
- **Flexible Configuration**: Configure JSON parsing per jail or filter

Configuration
-------------

JSON parsing can be configured at both the filter and jail level.

Filter Configuration
~~~~~~~~~~~~~~~~~~~

In your filter configuration file (e.g., ``filter.d/myapp.conf``):

.. code-block:: ini

    [Definition]
    
    # Enable JSON parsing
    jsonparsing = yes
    
    # JSONPath expressions to extract data
    jsonpath = $.remote_addr $.method $.uri $.status_code
    
    # JSONPath expressions for ignore conditions
    jsonignorepath = $.status_code
    
    # Regular expressions to match on extracted data
    failregex = ^json_field_0=<HOST> json_field_1=POST json_field_2=/login json_field_3=(401|403)$

Jail Configuration
~~~~~~~~~~~~~~~~~

In your jail configuration file (e.g., ``jail.d/myapp.conf``):

.. code-block:: ini

    [myapp]
    
    enabled = true
    port = http,https
    filter = myapp
    logpath = /var/log/myapp/access.json
    maxretry = 3
    bantime = 600
    
    # JSON parsing configuration
    jsonparsing = yes
    jsonpath = $.remote_addr $.method $.uri $.status_code
    jsonignorepath = $.status_code

JSONPath Syntax
--------------

The JSONPath implementation supports the following syntax:

- ``$.field`` - Access a field directly
- ``$.field.subfield`` - Access nested fields
- ``$['field']`` - Access fields with special characters
- ``$[0]`` - Access array elements
- ``$.field[0]`` - Access nested array elements

Examples:

.. code-block:: json

    {
        "timestamp": "2024-01-01T12:00:00Z",
        "request": {
            "remote_addr": "192.168.1.100",
            "method": "POST",
            "uri": "/login",
            "status": 401
        },
        "user": {
            "id": 123,
            "name": "testuser"
        }
    }

JSONPath expressions:

- ``$.request.remote_addr`` → ``"192.168.1.100"``
- ``$.request.method`` → ``"POST"``
- ``$.user.name`` → ``"testuser"``
- ``$.timestamp`` → ``"2024-01-01T12:00:00Z"``

Usage Examples
-------------

Caddy Web Server
~~~~~~~~~~~~~~~

Caddy JSON log format:

.. code-block:: json

    {
        "level": "info",
        "ts": 1640995200.123,
        "msg": "handled request",
        "request": {
            "remote_addr": "192.168.1.100",
            "method": "POST",
            "uri": "/login",
            "status": 401
        }
    }

Filter configuration:

.. code-block:: ini

    [Definition]
    
    jsonparsing = yes
    jsonpath = $.request.remote_addr $.request.method $.request.uri $.request.status
    jsonignorepath = $.request.status
    
    failregex = ^json_field_0=<HOST> json_field_1=POST json_field_2=/login json_field_3=(401|403)$
    
    datepattern = ^.*"ts":(\d+\.\d+).*$

MongoDB
~~~~~~~

MongoDB JSON log format:

.. code-block:: json

    {
        "t": {"$date": "2024-01-01T12:00:00.000Z"},
        "s": "I",
        "c": "ACCESS",
        "id": 20249,
        "ctx": "conn1",
        "msg": "Authentication failed",
        "attr": {
            "mechanism": "SCRAM-SHA-1",
            "speculative": false,
            "principalName": "user@database",
            "authenticationDatabase": "admin",
            "remote": "192.168.1.100:12345",
            "extraInfo": "AuthenticationFailed: Authentication failed."
        }
    }

Filter configuration:

.. code-block:: ini

    [Definition]
    
    jsonparsing = yes
    jsonpath = $.attr.remote $.attr.principalName $.msg
    
    failregex = ^json_field_0=<HOST>.* json_field_1=.* json_field_2=Authentication failed$
    
    datepattern = ^.*"t":\{"\$date":"([^"]+)"\}.*$

GitLab
~~~~~~

GitLab JSON log format:

.. code-block:: json

    {
        "time": "2024-01-01T12:00:00.000Z",
        "severity": "WARN",
        "message": "Failed to authenticate user",
        "remote_ip": "192.168.1.100",
        "user": "testuser",
        "action": "login"
    }

Filter configuration:

.. code-block:: ini

    [Definition]
    
    jsonparsing = yes
    jsonpath = $.remote_ip $.user $.action $.message
    
    failregex = ^json_field_0=<HOST> json_field_1=.* json_field_2=login json_field_3=Failed to authenticate user$
    
    datepattern = ^.*"time":"([^"]+)".*$

Command Line Usage
-----------------

You can also configure JSON parsing via the fail2ban-client:

.. code-block:: bash

    # Enable JSON parsing for a jail
    fail2ban-client set myapp jsonparsing yes
    
    # Set JSONPath expressions
    fail2ban-client set myapp jsonpath "$.remote_addr $.method $.uri"
    
    # Set ignore conditions
    fail2ban-client set myapp jsonignorepath "$.status_code"
    
    # Check current settings
    fail2ban-client get myapp jsonparsing
    fail2ban-client get myapp jsonpath
    fail2ban-client get myapp jsonignorepath

Benefits
--------

1. **Robustness**: JSON parsing is more reliable than regex for structured data
2. **Maintainability**: Easier to understand and modify than complex regex patterns
3. **Performance**: Compiled JSONPath expressions are efficient
4. **Flexibility**: Can handle changes in JSON structure more gracefully
5. **Debugging**: Easier to debug and test than regex patterns

Limitations
-----------

1. **JSONPath Support**: Limited to basic JSONPath syntax (no wildcards, filters, etc.)
2. **Performance**: Slight overhead for JSON parsing vs. direct regex matching
3. **Compatibility**: Requires Python 3.6+ for f-string support

Migration from Regex
-------------------

To migrate from regex-based JSON parsing:

1. **Identify JSON fields**: Determine which fields you need to extract
2. **Create JSONPath expressions**: Map regex patterns to JSONPath
3. **Update failregex**: Modify patterns to work with extracted data
4. **Test thoroughly**: Verify behavior matches original configuration

Example migration:

**Before (regex-based):**
.. code-block:: ini

    failregex = ^.*"remote_addr":"<HOST>".*"method":"POST".*"uri":"/login".*"status":(401|403).*$

**After (JSON parsing):**
.. code-block:: ini

    jsonparsing = yes
    jsonpath = $.remote_addr $.method $.uri $.status
    failregex = ^json_field_0=<HOST> json_field_1=POST json_field_2=/login json_field_3=(401|403)$

Troubleshooting
--------------

Common issues and solutions:

1. **JSON parsing not working**: Check that `jsonparsing = yes` is set
2. **No matches found**: Verify JSONPath expressions are correct
3. **Performance issues**: Consider using more specific JSONPath expressions
4. **Date parsing errors**: Ensure datepattern matches the JSON timestamp format

Debugging tips:

1. Enable debug logging: `fail2ban-client set loglevel DEBUG`
2. Check extracted data in logs
3. Test JSONPath expressions independently
4. Verify JSON log format matches expectations 